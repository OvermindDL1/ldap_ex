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


  defmodule LDAPException do
    defexception type: :error, message: "<UNKNOWN LDAP EXCEPTION"
  end


  ### This file is heavily based off of Erlangs eldap package:
  # https://github.com/erlang/otp/blob/e1489c448b7486cdcfec6a89fea238d88e6ce2f3/lib/eldap/src/eldap.erl


  ####
  #
  # Public Interface
  #
  ####

  @doc """
  Call this to start the client and link it to your process so it will be
  cleaned when your process exits, it will return {:ok, pid}.  Any of the
  default config options can (and should be if not specified in the config) be
  specified here as a keyword list.

  ```elixir

  iex> {:ok, ldap} = LDAPEx.Client.start_link()
  iex> is_pid(ldap)
  true

  # Anon login
  iex> {:ok, ldap} = LDAPEx.Client.start_link(username: "", password: "")
  iex> is_pid(ldap)
  true

  iex> LDAPEx.Client.start_link(username: "INVALID", password: "")
  {:error, :invalidDNSyntax}

  iex> LDAPEx.Client.start_link(username: System.get_env("TEST_LDAP_DN"), password: "INCORRECT")
  {:error, :invalidCredentials}

  ```
  """
  def start_link(overrides \\ []) do
    config = LDAPEx.Config.get_config(overrides)
    # old_trap = Process.flag(:trap_exit, true)
    # ret = try do
    #   GenServer.start_link(__MODULE__, config)
    # rescue
    #   res -> {:RES, res}
    # catch
    #   :exit, res -> {:exit, res}
    #   err -> {:ERR, err}
    # end
    # Process.flag(:trap_exit, old_trap)
    # ret
    try do
      GenServer.start(__MODULE__, config)
    catch
      :exit, reason -> {:error, {:exit, reason}}
    else
      {:ok, pid} when is_pid(pid) ->
        Process.link(pid)
        {:ok, pid}
      ret -> ret
    end
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

  Details on the LDAP Searching spec can be found at the
  [LDAP Website - The Search Operation](https://www.ldap.com/the-ldap-search-operation)

  Details about LDAP Filters can be found at the
  [LDAP Website - Filters](https://www.ldap.com/ldap-filters).

  All possible options are:
  * `:baseObject` -> Specifies the base DN for the search. Only entries at or
    below this location in the server (based on the scope) will be considered
    potential matches.
  * `:scope` -> Specifies the range of entries relative to the base DN that may
    be considered potential matches.  By default it is `:wholeSubtree`, which
    can be slow for many operations.  Can also be set to the atoms
    `:singleLevel` or `:baseObject`.
  * `:derefAliases` -> Specifies the behavior that the server should exhibit if
    any alias entries are encountered while processing the search.  This should
    generally always be left at its default atom of `:derefAlways`, however its
    other options are the atoms of `:derefFindingBaseObj`, `:derefInSearching`,
    and `:neverDerefAliases`.
  * `:sizeLimit` -> An integer that specifies the maximum number of entries that
    should be returned from the search. A value of zero indicates that there
    should not be any limit enforced. Note that the directory server may also be
    configured with a server-side size limit which can also limit the number of
    entries that may be returned to the client and in that case the smaller of
    the client-side and server-side limits will be used. If no size limit is
    provided, then a default of zero (unlimited) will be used.
  * `:timeLimit` -> Specifies the maximum length of time in seconds that the
    server should spend processing the search. A value of zero indicates that
    there should not be any limit enforced. Note that the directory server may
    also be configured with a server-side time limit which can also limit the
    processing time, and in that case the smaller of the client-side and
    server-side limits will be used. If no time limit is provided, then a
    default of the initial connection timeout value will be used.
  * `:typesOnly` -> Indicates whether matching entries should include only
    attribute names, or both attribute names and values. If no value is
    provided, then a default of `false` will be used.  Other option is `true`.
    If it is `true` then the attribute values will just be the empty list `[]`.
  * `:filter` -> A filter is a 2-tuple of one of the following:
      + `{:and, [<AnotherFilter>]}` -> And takes a list of other filters and
        requires them all.
      + `{:or, [<AnotherFilter>]}` -> Or takes a list of other filters and
        requires them all.
      + `{:not, <AnotherFilter}` -> Not will invert another Filter.
      + `{:equalityMatch, {:AttributeValueAssertion, "<AttributeKey>", "<AttributeValue>"}}` ->
        Equality Match takes an attribute key string and an attribute value string
        then filters on if the value matches the attribute value on the object.
      + `{:substrings, {:SubstringFilter, "<AttributeKey>", [<SubstringMatcher>]}}` ->
        Substring takes an Attribute Key string, and a list of
        SubstringMaterchers, which are a 2-tuple of
        `{:initial|:any|:final, "<String>"}`.
      + `{:greaterOrEqual, {:AttributeValueAssertion, "<AttributeKey>", "<AttributeValue"}}` ->
        GreaterOrEqual takes an attribute key string and an attribute value string
        then filters on if the value is greater or equal to the attribute value on
        the object.
      + `{:lessOrEqual, {:AttributeValueAssertion, "<AttributeKey>", "<AttributeValue>"}}` ->
        LessOrEqual takes an attribute key string and an attribute value string
        then filters on if the value is less or equal to the attribute value on
        the object.
      + {:present, "<AttributeKey>"} -> Present takes a single string and will
        match to an object if it contains that Attribute Key at all, or filters it
        out if it does not have that Attribute key.
      + `{:approxMatch, {:AttributeValueAssertion, "<AttributeKey>", "<AttributeValue>"}}` ->
        ApproxMatch takes an attribute key string and an attribute value string
        then filters on if the value is approximately  to the attribute value on
        the object.  By 'approximately' this means that the implementation is
        entirely defined by and dependent on the server.  It might be phonetic, so
        something like 'John' could match 'Jon', or it could be a LIKE type thing
        so "Joh*" could match "John" or "Johnny" or whatever it is the server
        wants to do.
      + `{:extensibleMatch, {:MatchingRuleAssertion, matchingRule = :asn1_NOVALUE,
        type = :asn1_NOVALUE, matchValue, dnAttributes = :asn1_DEFAULT}}` ->
        The Extensible Match is the most complex, but also the most powerful
        matcher that LDAP has to offer.  Please see the "Extensible Match Filters"
        section on the above LDAP Filters link for details.  'matchingRule',
        'type', and 'matchValue' are all strings, and 'dnAttributes' is a boolean.
        'matchValue' is the only required field, the rest may be left at the
        defaults that are listed above to have the server ignore those fields.
        The atom `:asn1_DEFAULT` on `dnAttributes` is equal to `false`.
  * `:attributes` -> A list of strings, default [], will return only the
    specified attributes, if empty it returns all.

  ```elixir

  iex> LDAPEx.Client.setup_search(baseObject: "ou=People,o=example.com,o=cp", filter: {:present, "dn"} )
  {:SearchRequest, "ou=People,o=example.com,o=cp", :wholeSubtree,
    :derefAlways, 0, :undefined, false, {:present, "dn"}, []}

  ```
  """
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


  @doc """
  This performs a search in the LDAP connection using the record created by
  `LDAPEx.Client.setup_search/1`.

  ```elixir

  iex> {:ok, ldap} = LDAPEx.Client.start_link()
  iex> req = LDAPEx.Client.setup_search(baseObject: System.get_env("TEST_LDAP_DN"), filter: {:present, "objectClass"} )
  iex> {:ok, {res, _references}} = LDAPEx.Client.search(ldap, req) # _refs are just an empty [] in every server tested so far...
  iex> [r] = res # Assuming only one record is returned
  iex> r.objectName === System.get_env("TEST_LDAP_DN")
  true
  iex> map_size(r.attributes) >= 1
  true
  iex> LDAPEx.Client.close(ldap)
  :ok

  ```
  """
  def search(ldap, searchRecord, genserver_timeout \\ 120000, controls \\ :asn1_NOVALUE) when is_pid(ldap) and is_record(searchRecord, :SearchRequest) do
    GenServer.call(ldap, {:search, searchRecord, controls}, genserver_timeout)
  end


  @doc """
  This returns an object by a full object name, optionally can specify specific
  attributes to return, otherwise it returns all.  This function ignores
  references and will only return a single full object result.  If more than one
  object matched then the dn was not precise enough and it will return an
  `{:error, reason}` 2-tuple.

  ```elixir

  iex> {:ok, ldap} = LDAPEx.Client.start_link()
  iex> {:ok, obj} = LDAPEx.Client.get_object(ldap, System.get_env("TEST_LDAP_DN"))
  iex> obj.objectName === System.get_env("TEST_LDAP_DN")
  true
  iex> map_size(obj.attributes) >= 1
  true
  iex> LDAPEx.Client.close(ldap)
  :ok

  ```
  """
  def get_object(ldap, dn, attributes \\ [], genserver_timeout \\ 120000) do
    GenServer.call(ldap, {:get_object, dn, attributes}, genserver_timeout)
  end



  ####
  #
  # GenServer Callbacks
  #
  ####

  # Don't call this one with login_at_connect: false yet, no way to log in yet if not now...
  # def init(%{server: server, port: port, ssl: ssl, timeout: timeout, login_at_connect: false} = config) do
  #   {:ok, connection} = try_connect(config)
  #   state = %LDAPEx.Client{fd: connection, using_tls: ssl, config: config}
  #   {:ok, state}
  # end

  def init(%{ssl: ssl, username: username, password: password} = config) do
    {:ok, fd} = try_connect(config)
    state = %LDAPEx.Client{fd: fd, using_tls: ssl, config: config}
    case do_simple_bind(state, username, password, :asn1_NOVALUE) do
      {:ok, newState} -> {:ok, put_in(newState.config[:password], nil)} # Sanitize password
      {{:ok, {:referral, referral}}, _newState} ->
        do_unbind(bump_id(state))
        {:stop, {:referral, referral}}
      {{:error, err}, _newState} ->
        do_unbind(bump_id(state))
        {:stop, err}
    end
  end


  def handle_call({:search, searchRecord, controls}, _from, state) do
    {res, newState} = do_search(bump_id(state), searchRecord, controls)
    {:reply, res, newState}
  end

  def handle_call({:get_object, dn, attributes}, _from, state) do
    {res, newState} = do_get_object(bump_id(state), dn, attributes)
    {:reply, res, newState}
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
  defp bump_id(%{id: id} = state) do
    %{state | id: bump_id_safe(id+1)}
  end


  defp bump_id_safe(id) when is_integer(id) and id>=0 and id<=2147483647 do
    id+1
  end
  defp bump_id_safe(id) when is_integer(id) and id>2147483647 do
    0 # Is it safe to wrap around?  Will this ever happen in reality?
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
    rescue
      _ -> {:error, :ldap_closed}
    catch
      _ -> {:error, :ldap_closed}
    else
      {:error, _res} -> {:error, :ldap_closed}
      _ -> {:error, emsg}
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


  defp do_recv(%{fd: fd, using_tls: false, config: %{timeout: timeout}}, len) do
    :gen_tcp.recv(fd, len, timeout)
  end

  defp do_recv(%{fd: fd, using_tls: true, config: %{timeout: timeout}}, len) do
    :ssl.recv(fd, len, timeout)
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


  ### Bind requests

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


  ###
  ### Polish the returned search result
  ###

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


  ## Get Object

  defp do_get_object(state, dn, attributes) do
    searchRecord = LDAPEx.Client.setup_search(
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

end
