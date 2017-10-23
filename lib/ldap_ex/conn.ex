defmodule LDAPEx.Conn do
  ### This file is heavily based off of Erlangs eldap package:
  # https://github.com/erlang/otp/blob/e1489c448b7486cdcfec6a89fea238d88e6ce2f3/lib/eldap/src/eldap.erl

  @moduledoc false
  use Connection

  require Logger
  require LDAPEx.ELDAPv3

  require Record
  import Record, only: [is_record: 2]

  defmodule State do
    @ldap_version 3
    defstruct [
      fd: nil,
      id: 0,
      backoff: nil,
      using_tls: false,
      config: %{},
      version: @ldap_version
    ]
  end

  defmodule LDAPException do
    defexception type: :error, message: "<UNKNOWN LDAP EXCEPTION"
  end


  def start_link(ldap_opts \\ [], gs_opts \\ []) do
    result = Connection.start_link(__MODULE__, ldap_opts, gs_opts)
    Logger.log(:info, "start_link returns: #{inspect result}")
    result
  end

  def stop(conn, timeout \\ :infinity) do
    GenServer.stop(conn, :normal, timeout)
  end

  def setup_search(searchRequestArgs \\ []) do
    default = LDAPEx.ELDAPv3."SearchRequest"(
      baseObject: :BASE_INVALID,
      scope: v_scope(:wholeSubtree),
      derefAliases: v_deref(:derefAlways),
      sizeLimit: v_integer_nonneg(0, "sizeLimit"),
      timeLimit: :undefined,
      typesOnly: v_bool(false),
      filter: :FILTER_INVALID,
      attributes: v_attributes([])
      )
    parse_into_searchRequest(searchRequestArgs, default)
  end

  def search(ldap, searchRecord, genserver_timeout \\ 120000, controls \\ :asn1_NOVALUE) when is_pid(ldap) and is_record(searchRecord, :SearchRequest) do
    GenServer.call(ldap, {:search, searchRecord, controls}, genserver_timeout)
  end

  def get_object(ldap, dn, attributes \\ [], genserver_timeout \\ 120000) do
    GenServer.call(ldap, {:get_object, dn, attributes}, genserver_timeout)
  end


  ####
  #
  # Callbacks
  #
  ####

  def init(ldap_opts) do
    state = %State{config: LDAPEx.Config.get_config(ldap_opts)}
    if ldap_opts[:async_conn] == true do
      {:connect, :initial_connection, state}
    else
      case do_connect(:initial_connection, state) do
        {:ok, _state} = result -> result
        {:error, reason, _state} -> {:stop, reason}
      end
    end
  end

  def connect(info, state) do
    case do_connect(info, state) do
      {:ok, state} ->
        {:ok, %{state | backoff: nil, id: 0}}
      {:error, reason, state} ->
        if reason == :invalidCredentials do
          {:stop, reason, state}
        else
          state = update_backoff(state)
          {:backoff, state.backoff, state}
        end
    end
  end

  def disconnect({:error, reason}, state) do
    Logger.log(:error, "LDAPEx disconnected: #{inspect reason}")
    ldap_closed_p(state, reason)
    {:connect, :reconnect, %{state | fd: nil, backoff: nil, id: 0}}
  end

  def terminate(reason, state) do
    Logger.log(:info, "LDAPEx terminating connection: #{inspect reason}")
    ldap_closed_p(state, reason)
    :ok
  end

  def handle_call(_msg, _from, %{fd: nil} = state) do
    {:reply, {:error, :not_connected}, state}
  end

  def handle_call({:search, searchRecord, controls}, _from, state) do
    # {res, newState} = do_search(bump_id(state), searchRecord, controls)
    # {:reply, res, newState}
    case do_search(bump_id(state), searchRecord, controls) do
      {{:error, :ldap_closed} = error, state} -> {:disconnect, error, error, state}
      {result, state} -> {:reply, result, state}
    end
  end

  def handle_call({:get_object, dn, attributes}, _from, state) do
    # {res, newState} = do_get_object(bump_id(state), dn, attributes)
    # {:reply, res, newState}
    case do_get_object(bump_id(state), dn, attributes) do
      {{:error, :ldap_closed} = error, state} -> {:disconnect, error, error, state}
      {result, state} -> {:reply, result, state}
    end
  end

  def handle_cast(:close, state) do
    {:ok, newState} = do_unbind(bump_id(state))
    {:stop, :normal, newState}
  end


  ####
  #
  # Internal functions
  #
  ####

  defp do_connect(info, state) do
    config = state.config
    with {:ok, fd} <- try_connect(config),
         Logger.log(:info, "LDAPEx port opened: #{inspect fd}"),
         state = %{state | fd: fd, using_tls: config.ssl},
         {:ok, state} <- do_simple_bind(state, config.username, config.password, :asn1_NOVALUE)
    do
      if info in [:backoff, :reconnect] do
        Logger.log(:info, "LDAPEx reconnected: #{inspect fd}")
      end
      {:ok, %{state | backoff: nil, id: 0}}
    else
      {{:ok, {:referral, _referral}}, state} ->
        {:ok, state} = do_unbind(bump_id(state))
        {:error, :referral_unsupported, state}
      {{:error, reason}, state} ->
        {:ok, state} = do_unbind(bump_id(state))
        {:error, reason, state}
      {:error, reason} ->
        Logger.log(:error, "LDAPEx failed to connect: #{inspect reason} - backoff: #{inspect state.backoff}")
        {:error, reason, state}
    end
  end

  defp try_connect(%{server: server, port: port, ssl: false, timeout: timeout}) do
    tcpOpts = [:binary, packet: :asn1, active: false]
    :gen_tcp.connect(to_charlist(server), port, tcpOpts, timeout)
  end

  defp try_connect(%{server: server, port: port, ssl: true, timeout: timeout}) do
    tcpOpts = [:binary, packet: :asn1, active: false]
    tlsOpts = []
    :ssl.connect(server, port, tcpOpts ++ tlsOpts, timeout)
  end

  # TODO: Move to config
  @backoff_min 1000
  @backoff_max 30_000

  defp update_backoff(state) do
    backoff =
      case state.backoff do
        nil -> @backoff_min
        backoff when backoff * 2 <= @backoff_max -> backoff * 2
        _ -> @backoff_max
      end
    %{state | backoff: backoff}
  end


  defp ldap_closed_p(%{fd: fd, using_tls: true} = _state, emsg) do
    ## Check if the SSL socket seems to be alive or not
    try do
      :ssl.sockname(fd)
    rescue
      _ -> {:error, :ldap_closed}
    catch
      _ -> {:error, :ldap_closed}
    else
      {:ok, _res} -> {:error, emsg}
      {:error, _res} ->
        :ssl.close(fd)
        {:error, :ldap_closed}
      #_ -> {:error, :ldap_closed}
    end
  end

  defp ldap_closed_p(%{fd: fd, using_tls: false} = _state, emsg) do
    ## Non-SSL socket
    try do
      :inet.port(fd)
      Logger.log(:info, "LDAPEx port closed")
    rescue
      _ -> {:error, :ldap_closed}
    catch
      _ -> {:error, :ldap_closed}
    else
      {:error, _res} -> {:error, :ldap_closed}
      _ -> {:error, emsg}
    end
  end


  ####
  #
  # LDAP request/response functions
  #
  ####

  ### Bind request

  defp do_simple_bind(state, dn, password, controls) do
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
          err -> {{:error, err}, state}
        end
  end

  defp exec_simple_bind_reply(_, error) do
    {:error, error}
  end


  ### Unbind request

  defp do_unbind(state) do
    req = ""
    send_request(state, {:unbindRequest, req})
    do_final_unbind(state)
    {:ok, %{state | fd: nil, using_tls: false}}
  end

  defp do_final_unbind(%{fd: fd, using_tls: false} = _state) do
    :gen_tcp.close(fd)
  end

  defp do_final_unbind(%{fd: fd, using_tls: true} = _state) do
    :ssl.close(fd)
  end


  ### Get Object request

  defp do_get_object(state, dn, attributes) do
    searchRecord = setup_search(
      baseObject: dn,
      filter: {:present, "objectClass"},
      attributes: attributes
      )
    case do_search(state, searchRecord, :asn1_NOVALUE) do
      {{:ok, {[r], _refs}}, newState}                -> {{:ok, r}, newState}
      {{:ok, {[], _refs}}, newState}                 -> {{:error, :no_object_found}, newState}
      {{:ok, {[_r0, _r1 | _rest], _refs}}, newState} -> {{:error, :more_than_one_object_found}, newState}
      {{:ok, _unknown}, newState}                    -> {{:error, :non_object}, newState}
      {{:error, err}, newState}                      -> {{:error, err}, newState}
      #{unknown, newState}                            -> {{:error, {:unknown_error, unknown}}, newState}
    end
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
    parse_into_searchRequest(rest, LDAPEx.ELDAPv3."SearchRequest"(searchRequest, sizeLimit: v_integer_nonneg(sizeLimit, "sizeLimit")))
  end
  defp parse_into_searchRequest([{:timeLimit, timeLimit}|rest], searchRequest) do
    parse_into_searchRequest(rest, LDAPEx.ELDAPv3."SearchRequest"(searchRequest, timeLimit: v_integer_nonneg(timeLimit, "timeLimit")))
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
  defp v_deref(deref)                ,do: raise LDAPException, type: :invalid_deref, message: "unknown deref: #{deref}"

  defp v_scope(:baseObject)   ,do: :baseObject
  defp v_scope(:singleLevel)  ,do: :singleLevel
  defp v_scope(:wholeSubtree) ,do: :wholeSubtree
  defp v_scope(scope)         ,do: raise LDAPException, type: :invalid_scope, message: "unknown scope: #{scope}"

  defp v_bool(true)  ,do: true
  defp v_bool(false) ,do: false
  defp v_bool(bool)  ,do: raise LDAPException, type: :invalid_bool, message: "not Boolean: #{bool}"

  defp v_integer_nonneg(i, _type) when is_integer(i) and i>=0 and i<=2147483647 ,do: i
  defp v_integer_nonneg(i, type) ,do: raise LDAPException, type: :invalid_nonneg_integer, message: "#{type} not positive integer between 0 and 2147483647: #{i}"

  defp v_attributes(attrs) when is_list(attrs) do
    attrs
    |> Enum.map(fn
      a when is_binary(a) or is_list(a) -> a
      a -> raise LDAPException, type: :invalid_attribute, message: "attribute not a string: #{a}"
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
  defp v_filter(filter)                ,do: raise LDAPException, type: :invalid_filter, message: "unknown filter: #{filter}"


  ### Search

  defp do_search(state, searchRecord, controls) do
    searchRecord = add_search_timeout(state, searchRecord)
    try do
      collect_search_responses(state, searchRecord, controls)
    rescue
      e in LDAPException -> {ldap_closed_p(state, e), state}
    catch
      {:error, emsg}               -> {ldap_closed_p(state, emsg), state}
      {:EXIT, err}                 -> {ldap_closed_p(state, err), state}
      otherwise                    -> {ldap_closed_p(state, otherwise), state}
    else
      {:ok, res, ref, newState}    -> {{:ok, polish(res, ref)}, newState}
      {{:ok, val}, newState}       -> {{:ok, val}, newState}
      {{:error, reason}, newState} -> {{:error, reason}, newState}
      #otherwise                    -> {ldap_closed_p(state, otherwise), state}
    end
  end

  defp add_search_timeout(%{config: %{timeout: timeout}} = _state, searchRecord) do
    LDAPEx.ELDAPv3."SearchRequest"(timeLimit: timeLimit) = searchRecord
    case timeLimit do
      :undefined -> LDAPEx.ELDAPv3."SearchRequest"(searchRecord, timeLimit: round(timeout/1000))
      _ -> searchRecord
    end
  end

  ### Polish the returned search result
  defp polish(res, ref) do
    r = polish_result(res)
    ### No special treatment of referrals at the moment.
    #eldap_search_result{entries = R,
  	#	 referrals = Ref}.
    {r, ref}
  end

  defp polish_result([h|t]) when is_record(h, :SearchResultEntry) do
    LDAPEx.ELDAPv3."SearchResultEntry"(objectName: objectName, attributes: attributes) = h
    f = fn {_, a, v} -> {a, v} end
    attrs = Enum.map(attributes, f) |> Enum.into(%{})
    [%{objectName: objectName, attributes: attrs} | polish_result(t)]
  end
  defp polish_result([]), do: []

  ### The returned answers cames in one packet per entry
  ### mixed with possible referals
  defp collect_search_responses(state, searchRecord, controls) do
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
      otherwise -> raise LDAPException, type: :search_failure, message: otherwise
    end
  end

  defp collect_search_responses(_state, msg, _acc, _ref) do
    raise LDAPException, type: :search_invalid, message: msg
  end


  ### Core LDAP request/response handling

  defp bump_id(%{id: id} = state) do
    %{state | id: bump_id_safe(id+1)}
  end

  defp bump_id_safe(id) when is_integer(id) and id>=0 and id<=2147483647 do
    id+1
  end
  defp bump_id_safe(id) when is_integer(id) and id>2147483647 do
    0 # Is it safe to wrap around?  Will this ever happen in reality?
  end

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
    {:ok, bytes} = LDAPEx.ELDAPv3.encode(:LDAPMessage, ldapMessage)
    case do_send(state, bytes) do
      {:error, reason} -> raise LDAPException, type: :gen_tcp_error, message: reason
      response -> response
    end
  end


  defp do_send(%{fd: fd, using_tls: false}, bytes) do
    :gen_tcp.send(fd, bytes)
  end

  defp do_send(%{fd: fd, using_tls: true}, bytes) do
    :ssl.send(fd, bytes)
  end


  defp recv_response(state) do
    case do_recv(state, 0) do
      {:ok, packet} ->
        case LDAPEx.ELDAPv3.decode(:LDAPMessage, packet) do
          {:ok, resp} -> {:ok, resp}
          error -> raise LDAPException, type: :decode_error, message: error
        end
      {:error, reason} -> raise LDAPException, type: :gen_tcp_error, message: reason
    end
  end

  defp do_recv(%{fd: fd, using_tls: false, config: %{timeout: timeout}}, len) do
    :gen_tcp.recv(fd, len, timeout)
  end

  defp do_recv(%{fd: fd, using_tls: true, config: %{timeout: timeout}}, len) do
    :ssl.recv(fd, len, timeout)
  end


  ### The check_reply function is not used just yet...
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
  # Hmm, the below is a more complex matcher, but it is so much shorter and kind
  # of more readable...
  # defp check_reply(%{id: id} = state,
  #   {:ok, {:LDAPMessage, id,
  #     {op, {:LDAPResult, :success, _matchedDN, _errorMessage, _referral}}, _controls}=msg},
  #     op) do
  #       {:ok, state}
  # end
  # defp check_reply(%{id: id} = state,
  #   {:ok, {:LDAPMessage, id,
  #     {op, {:LDAPResult, :referral, _matchedDN, _errorMessage, referral}}, _controls}=msg},
  #     op) do
  #       {{:ok, {:referral, referral}}, state}
  # end
  # defp check_reply(_, error, _) do
  #   {:error, error}
  # end
end
