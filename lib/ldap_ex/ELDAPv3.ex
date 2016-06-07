defmodule LDAPEx.ELDAPv3 do
  require Record
  import Record, only: [defrecord: 2, extract: 2, extract_all: 1, is_record: 2]

  for rec <- extract_all(from: "include/ELDAPv3.hrl") do
    defrecord elem(rec, 0), elem(rec, 1)
  end

  # for rec <- extract_all(from: "include/eldap.hrl") do
  #   defrecord elem(rec, 0), elem(rec, 1)
  # end
end
