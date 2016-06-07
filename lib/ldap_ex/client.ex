defmodule LDAPEx.Client do
  @moduledoc """
  This handles the LDAP communications over the TCP or SSL connections.
  """
  use GenServer

  require Logger

  require LDAPEx.ELDAPv3

  require Record
  import Record, only: [is_record: 2]


  @ldap_version 3

  defstruct fd: nil, using_tls: false, id: 0, version: @ldap_version, config: %{}


  ####
  #
  # Public Interface
  #
  ####

  @doc """
  Call this to start the client, it will return {:ok, pid}.

  ```elixir

  iex> {:ok, ldap} = LDAPEx.Client.start_link()
  iex> is_pid(ldap)
  true

  ```
  """
  def start_link(overrides \\ []) do
    config = LDAPEx.Config.get_config(overrides)
    GenServer.start_link(__MODULE__, config)
  end


  @doc """
  This will close the supplied `LDAPEx.Client`.

  ```elixir

  iex> {:ok, ldap} = LDAPEx.Client.start_link()
  iex> is_pid(ldap)
  true
  iex> LDAPEx.Client.close(ldap)
  :ok

  ```
  """
  def close(ldap) when is_pid(ldap) do
    GenServer.cast(ldap, :close)
  end


  @doc """
  This sets up a search record, this should then be passed into
  `LDAPEx.Client.search/3` to perform the search. The `:baseObject` and
  `:filter` options are the minimum necessary to be supplied.

  ```elixir

  iex> LDAPEx.Client.setup_search(baseObject: "ou=People,o=example.com,o=cp", filter: {:present, "dn"} )
  {:SearchRequest, "ou=People,o=example.com,o=cp", :wholeSubtree,
    :derefAlways, :undefined, :undefined, :undefined, {:present, "dn"},
    :undefined}

  ```
  """
  def setup_search(searchRequestArgs \\ []) do
    default = LDAPEx.ELDAPv3."SearchRequest"(scope: v_scope(:wholeSubtree), derefAliases: v_deref(:derefAlways))
    req = parse_into_searchRequest(searchRequestArgs, default)
    #req = LDAPEx.ELDAPv3."SearchRequest"(default, searchRequestArgs)
    #Req = #'SearchRequest'{baseObject = A#eldap_search.base,
    # scope = v_scope(A#eldap_search.scope),
    # derefAliases = v_deref(A#eldap_search.deref),
    # sizeLimit = 0, % no size limit
    # timeLimit = v_timeout(A#eldap_search.timeout),
    # typesOnly = v_bool(A#eldap_search.types_only),
    # filter = v_filter(A#eldap_search.filter),
    # attributes = v_attributes(A#eldap_search.attributes)
    #}
  end


  @doc """
  This performs a search in the LDAP connection using the record created by
  `LDAPEx.Client.setup_search/1`.

  ```elixir

  iex> {:ok, ldap} = LDAPEx.Client.start_link()
  iex> req = LDAPEx.Client.setup_search(baseObject: System.get_env("TEST_LDAP_DN"), filter: {:present, "dn"} )
  iex> LDAPEx.Client.search(ldap, req)
  :ok
  iex> LDAPEx.Client.close(ldap)
  :ok

  ```
  """
  def search(ldap, searchRecord, controls \\ :asn1_NOVALUE) when is_pid(ldap) and is_record(searchRecord, :SearchRequest) do
    GenServer.call(ldap, {:search, searchRecord, controls})
  end


  ####
  #
  # GenServer Callbacks
  #
  ####
  # Don't call this one with login_at_connect: false yet, no way to log in yet if not now...
  def init(%{server: server, port: port, ssl: ssl, timeout: timeout, login_at_connect: false} = config) do
    {:ok, connection} = try_connect(config)
    state = %LDAPEx.Client{fd: connection, using_tls: ssl, config: config}
    {:ok, state}
  end

  def init(%{server: server, port: port, ssl: ssl, username: username, password: password, timeout: timeout} = config) do
    {:ok, connection} = try_connect(config)
    state = %LDAPEx.Client{fd: connection, using_tls: ssl, config: config}
    {:ok, _newstate} = do_simple_bind(state, username, password, :asn1_NOVALUE)
  end


  def handle_call({:search, searchRecord, controls}, _from, state) do
    {res, newState} = collect_search_responses(bump_id(state), searchRecord, controls)
    {:reply, res, newState}
  end


  def handle_cast(:close, state) do
    do_unbind(state)
    {:stop, :normal, %{state | fd: nil, using_tls: false, id: 0}}
  end

  ####
  #
  # Internal functions
  #
  ####
  defp bump_id(%{id: id} = state) do
    %{state | id: id+1}
  end


  defp try_connect(%{server: server, port: port, ssl: false, timeout: timeout}) do
    tcpOpts = [:binary, packet: :asn1, active: false]
    :gen_tcp.connect(to_char_list(server), port, tcpOpts, timeout)
  end
  defp try_connect(%{server: server, port: port, ssl: true, timeout: timeout}) do
    tcpOpts = [:binary, packet: :asn1, active: false]
    tlsOpts = []
    :ssl.connect(server, port, tcpOpts ++ tlsOpts, timeout)
  end


  defp do_unbind(state) do
    req = ""
    send_request(state, {:unbindRequest, req})
  end


  defp do_final_unbind(%{fd: fd, using_tls: false} = state) do
    :gen_tcp.close(fd)
  end

  defp do_final_unbind(%{fd: fd, using_tls: true} = state) do
    :ssl.close(fd)
  end


  ### Send an LDAP request and maybe get a response
  defp request(state, request) do
    send_request(state, request)
    recv_response(state)
  end


  defp send_request(%{id: id} = state, {t, p}) do
    send_the_LDAPMessage(state, LDAPEx.ELDAPv3."LDAPMessage"(messageID: id, protocolOp: {t, p}))
  end

  defp send_request(%{id: id} = state, {t, p, :asn1_NOVALUE}) do
    send_the_LDAPMessage(state, LDAPEx.ELDAPv3."LDAPMessage"(messageID: id, protocolOp: {t, p}))
  end

  defp send_request(%{id: id} = state, {t, p, controls0}) do
    controls = for {:control, f1, f2, f3} <- controls0 do
      LDAPEx.ELDAPv3."Control"(controlType: f1, criticality: f2, controlValue: f3)
    end
    send_the_LDAPMessage(state, LDAPEx.ELDAPv3."LDAPMessage"(messageID: id, protocolOp: {t, p},
      controls: controls))
  end


  defp send_the_LDAPMessage(state, ldapMessage) do
    {:ok, bytes} = :ELDAPv3.encode(:"LDAPMessage", ldapMessage)
    case do_send(state, bytes) do
      {:error, reason} -> raise {:gen_tcp_error, reason}
      response -> response
    end
  end


  defp do_send(%{fd: fd, using_tls: false}, bytes) do
    :gen_tcp.send(fd, bytes)
  end

  defp do_send(%{fd: fd, using_tls: true}, bytes) do
    :ssl.send(fd, bytes)
  end


  defp do_recv(%{fd: fd, using_tls: false, config: %{timeout: timeout}}, len) do
    :gen_tcp.recv(fd, len, timeout)
  end

  defp do_recv(%{fd: fd, using_tls: true, config: %{timeout: timeout}}, len) do
    :ssl.recv(fd, len, timeout)
  end


  defp recv_response(state) do
    case do_recv(state, 0) do
      {:ok, packet} ->
        case :"ELDAPv3".decode(:"LDAPMessage", packet) do
          {:ok, resp} -> {:ok, resp}
          error -> raise error
        end
      {:error, reason} -> raise {:gen_tcp_error, reason}
    end
  end

  # LDAPEx.ELDAPv3."LDAPMessage"(messageID: id, protocolOp: protocolOp)
  # -record('LDAPMessage',{messageID, protocolOp, controls = asn1_NOVALUE}).
  # {'LDAPMessage', messageID, protocolOp, controls = asn1_NOVALUE}
  # defp check_reply(%{id: id} = state, {:ok, {:"LDAPMessage", id, protocolOp, _controls}=msg}, op) do
  #   case protocolOp do
  #     {^op, result} when is_record(result, :"LDAPResult") ->
  #       #LDAPEx.ELDAPv3."LDAPResult"(resultCode: resultCode, referral: referral) = result
  #       # -record('LDAPResult',{resultCode, matchedDN, errorMessage, referral = asn1_NOVALUE}).
  #       # {'LDAPResult', resultCode, matchedDN, errorMessage, referral = asn1_NOVALUE}
  #       {:"LDAPResult", resultCode, _matchedDN, _errorMessage, referral} = result
  #       case resultCode do
  #         :success -> {:ok, state}
  #         :referral -> {{:ok, {:referral, referral}}, state}
  #         error -> {:error, error}
  #       end
  #     error -> {:error, error}
  #   end
  # end
  defp check_reply(%{id: id} = state,
    {:ok, {:"LDAPMessage", id,
      {op, {:"LDAPResult", :success, _matchedDN, _errorMessage, _referral}}, _controls}=msg},
      op) do
        {:ok, state}
  end

  defp check_reply(%{id: id} = state,
    {:ok, {:"LDAPMessage", id,
      {op, {:"LDAPResult", :referral, _matchedDN, _errorMessage, referral}}, _controls}=msg},
      op) do
        {{:ok, {:referral, referral}}, state}
  end

  defp check_reply(_, error, _) do
    {:error, error}
  end


  ### Bind requests

  defp do_simple_bind(state, dn, password, controls) do
    do_the_simple_bind(state, dn, password, controls)
  end


  defp do_the_simple_bind(state, dn, password, controls) do
    exec_simple_bind(bump_id(state), dn, password, controls)
  end


  # -record('BindRequest',{version, name, authentication}).
  # {'BindRequest', version, name, authentication}
  defp exec_simple_bind(%{version: version} = state, dn, password, controls) do
    #req = LDAPEx.ELDAPv3."BindRequest"(version: version, name: dn, authentication: {:simple, password}) # TODO:  Check if to_char_list is needed on these...
    req = {:BindRequest, version, dn, {:simple, password}}
    reply = request(state, {:bindRequest, req, controls})
    exec_simple_bind_reply(state, reply)
  end


  # -record('LDAPMessage',{messageID, protocolOp, controls = asn1_NOVALUE}).
  # {'LDAPMessage', messageID, protocolOp, controls = asn1_NOVALUE}
  # -record('BindResponse',{resultCode, matchedDN, errorMessage, referral = asn1_NOVALUE, serverSaslCreds = asn1_NOVALUE}).
  # {'BindResponse', resultCode, matchedDN, errorMessage, referral = asn1_NOVALUE, serverSaslCreds = asn1_NOVALUE}
  defp exec_simple_bind_reply(%{id: messageID} = state,
    {:ok, {:LDAPMessage, messageID, {:bindResponse,
      {:BindResponse, resultCode, _matchedDN, _errorMessage, referral, _serverSaslCreds}}, _controls}}) do
        case resultCode do
          :success -> {:ok, state}
          :referral -> {{:ok, {:referral, referral}}, state}
        end
  end

  defp exec_simple_bind_reply(_, error) do
    {:error, error}
  end

  ### Search setup


  defp parse_into_searchRequest([], searchRequest) do
    searchRequest
  end
  defp parse_into_searchRequest([{:baseObject, base}|rest], searchRequest) do
    parse_into_searchRequest(rest, LDAPEx.ELDAPv3."SearchRequest"(searchRequest, baseObject: base))
  end
  defp parse_into_searchRequest([{:scope, scope}|rest], searchRequest) do
    parse_into_searchRequest(rest, LDAPEx.ELDAPv3."SearchRequest"(searchRequest, scope: v_scope(scope)))
  end
  defp parse_into_searchRequest([{:derefAliases, derefAliases}|rest], searchRequest) do
    parse_into_searchRequest(rest, LDAPEx.ELDAPv3."SearchRequest"(searchRequest, derefAliases: v_deref(derefAliases)))
  end
  defp parse_into_searchRequest([{:sizeLimit, sizeLimit}|rest], searchRequest) do
    parse_into_searchRequest(rest, LDAPEx.ELDAPv3."SearchRequest"(searchRequest, sizeLimit: sizeLimit))
  end
  defp parse_into_searchRequest([{:timeLimit, timeLimit}|rest], searchRequest) do
    parse_into_searchRequest(rest, LDAPEx.ELDAPv3."SearchRequest"(searchRequest, timeLimit: v_timeout(timeLimit)))
  end
  defp parse_into_searchRequest([{:typesOnly, typesOnly}|rest], searchRequest) do
    parse_into_searchRequest(rest, LDAPEx.ELDAPv3."SearchRequest"(searchRequest, typesOnly: v_bool(typesOnly)))
  end
  defp parse_into_searchRequest([{:filter, filter}|rest], searchRequest) do
    parse_into_searchRequest(rest, LDAPEx.ELDAPv3."SearchRequest"(searchRequest, filter: v_filter(filter)))
  end
  defp parse_into_searchRequest([{:attributes, attributes}|rest], searchRequest) do
    parse_into_searchRequest(rest, LDAPEx.ELDAPv3."SearchRequest"(searchRequest, attributes: v_attributes(attributes)))
  end


  defp v_deref(:neverDerefAliases)   ,do: :neverDerefAliases
  defp v_deref(:derefInSearching)    ,do: :derefInSearching
  defp v_deref(:derefFindingBaseObj) ,do: :derefFindingBaseObj
  defp v_deref(:derefAlways)         ,do: :derefAlways

  defp v_scope(:baseObject)   ,do: :baseObject
  defp v_scope(:singleLevel)  ,do: :singleLevel
  defp v_scope(:wholeSubtree) ,do: :wholeSubtree
  defp v_scope(scope)         ,do: raise {:error, "unknown scope: #{scope}"}

  defp v_bool(true)  ,do: true
  defp v_bool(false) ,do: false
  defp v_bool(bool)  ,do: raise {:error, "not Boolean: #{bool}"}

  defp v_timeout(i) when is_integer(i) and i>=0 ,do: i
  defp v_timeout(i) ,do: raise {:error, "timeout not positive integer: #{i}"}

  defp v_attributes(attrs) when is_list(attrs) do
    attrs
    |> Enum.map(fn
      a when is_binary(a) or is_list(a) -> a
      a -> raise {:error, "attribute not a string: #{a}"}
    end)
  end

  defp v_filter({:and, l})             ,do: {:and, l}
  defp v_filter({:or,  l})             ,do: {:or,  l}
  defp v_filter({:not, l})             ,do: {:not, l}
  defp v_filter({:equalityMatch, av})  ,do: {:equalityMatch, av}
  defp v_filter({:greaterOrEqual, av}) ,do: {:greaterOrEqual, av}
  defp v_filter({:lessOrEqual, av})    ,do: {:lessOrEqual, av}
  defp v_filter({:approxMatch, av})    ,do: {:approxMatch, av}
  defp v_filter({:present, a})         ,do: {:present, a}
  defp v_filter({:substrings, s})      when is_record(s, :SubstringFilter)       ,do: {:substrings, s}
  defp v_filter({:extensibleMatch, s}) when is_record(s, :MatchingRuleAssertion) ,do: {:extensibleMatch, s}
  defp v_filter(filter)                ,do: raise {:error, "unknown filter: #{filter}"}


  defp do_search(state, searchRecord, controls) do
    res = try do
      collect_search_responses(state, searchRecord, controls)
    rescue
      err -> err
    catch
      err -> err
    end
    case res do
      {:error, emsg}               -> {ldap_closed_p(state, emsg), state};
      {:EXIT, err}                 -> {ldap_closed_p(state, err), state};
      {{:ok, val}, newState}        -> {{ok, val}, newState};
      {:ok, res, ref, newState}      -> {{ok, polish(res, ref)}, newState};
      {{:error, reason}, newState} -> {{error, reason}, newState};
      otherwise                    -> {ldap_closed_p(state, otherwise), state}
    end
  end


  ### The returned answers cames in one packet per entry
  ### mixed with possible referals
  defp collect_search_responses(%{fd: fd} = state, searchRecord, controls) do
    send_request(state, {:searchRequest, searchRecord, controls})
    resp = recv_response(state)
    collect_search_responses(state, resp, [], [])
  end

  # -record('LDAPMessage',{messageID, protocolOp, controls = asn1_NOVALUE}).
  # {:LDAPMessage, messageID, protocolOp, controls = asn1_NOVALUE}}
  # -record('LDAPResult',{resultCode, matchedDN, errorMessage, referral = asn1_NOVALUE}).
  # {:LDAPResult, resultCode, matchedDN, errorMessage, referral = asn1_NOVALUE}
  defp collect_search_responses(state, {:ok, msg}, acc, ref) when is_record(msg, :LDAPMessage) do
    case elem(msg, 2) do
      {:searchResDone, r} when is_record(r, :LDAPResult) ->
        case elem(r, 1) do
          :success -> {:ok, acc, ref, state}
          :referral -> {{:ok, {:referral, elem(r, 4)}}, state}
          reason -> {{:error, reason}, state}
        end
      {:searchResEntry, r} when is_record(r, :SearchResultEntry) ->
        resp = recv_response(state)
        collect_search_responses(state, resp, [r|acc], ref)
      # {:searchResRef, r} ->
      #   # This is entirely handled improperly, however does any LDAP server send these at all?
      #   resp = recv_response(state)
      #   collect_search_responses(state, resp, acc, [r|ref])
      otherwise -> raise {:error, otherwise}
    end
  end

  defp collect_search_responses(_state, msg, _acc, _ref) do
    raise {:error, msg}
  end

end
