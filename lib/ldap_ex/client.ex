defmodule LDAPEx.Client do
  @moduledoc """
  This handles the LDAP communications over the TCP or SSL connections.
  """

  require Record
  import Record, only: [is_record: 2]

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

  iex> {:ok, conn} = LDAPEx.Client.start_link()
  iex> is_pid(conn)
  true

  # Anon login
  iex> {:ok, conn} = LDAPEx.Client.start_link(username: "", password: "")
  iex> is_pid(conn)
  true

  iex> LDAPEx.Client.start_link(username: "INVALID", password: "")
  {:error, :invalidDNSyntax}

  iex> LDAPEx.Client.start_link(username: System.get_env("TEST_LDAP_DN"), password: "INCORRECT")
  {:error, :invalidCredentials}

  OOTB creates the connection synchronously. Passing `async_conn: true` as an
  override option makes this asynchronous.
  ```
  """
  def start_link(overrides \\ []) do
    LDAPEx.Conn.start_link(overrides)
  end

  @doc """
  This will close the supplied `LDAPEx.Client`.

  ```elixir

  iex> {:ok, conn} = LDAPEx.Client.start_link()
  iex> is_pid(conn)
  true
  iex> LDAPEx.Client.close(conn)
  :ok

  ```
  """
  def close(conn) when is_pid(conn) do
    LDAPEx.Conn.stop(conn)
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
    LDAPEx.Conn.setup_search(searchRequestArgs)
  end

  @doc """
  This performs a search in the LDAP connection using the record created by
  `LDAPEx.Client.setup_search/1`.

  ```elixir

  iex> {:ok, conn} = LDAPEx.Client.start_link()
  iex> req = LDAPEx.Client.setup_search(baseObject: System.get_env("TEST_LDAP_DN"), filter: {:present, "objectClass"} )
  iex> {:ok, {res, _references}} = LDAPEx.Client.search(conn, req) # _refs are just an empty [] in every server tested so far...
  iex> [r] = res # Assuming only one record is returned
  iex> r.objectName === System.get_env("TEST_LDAP_DN")
  true
  iex> map_size(r.attributes) >= 1
  true
  iex> LDAPEx.Client.close(conn)
  :ok

  ```
  """
  def search(conn, searchRecord, genserver_timeout \\ 120000, controls \\ :asn1_NOVALUE)
        when is_pid(conn) and is_record(searchRecord, :SearchRequest) do
    LDAPEx.Conn.search(conn, searchRecord, genserver_timeout, controls)
  end

  @doc """
  This returns an object by a full object name, optionally can specify specific
  attributes to return, otherwise it returns all.  This function ignores
  references and will only return a single full object result.  If more than one
  object matched then the dn was not precise enough and it will return an
  `{:error, reason}` 2-tuple.

  ```elixir

  iex> {:ok, conn} = LDAPEx.Client.start_link()
  iex> {:ok, obj} = LDAPEx.Client.get_object(conn, System.get_env("TEST_LDAP_DN"))
  iex> obj.objectName === System.get_env("TEST_LDAP_DN")
  true
  iex> map_size(obj.attributes) >= 1
  true
  iex> LDAPEx.Client.close(conn)
  :ok

  ```
  """
  def get_object(conn, dn, attributes \\ [], genserver_timeout \\ 120000) do
    LDAPEx.Conn.get_object(conn, dn, attributes, genserver_timeout)
  end
end
