defmodule LDAPEx.ELDAPv3 do
  require Record
  import Record, only: [defrecord: 2, extract_all: 1, is_record: 2]


  for rec <- extract_all(from: "lib/asn1/ELDAPv3a.hrl") do
    defrecord elem(rec, 0), elem(rec, 1)
  end


  def encode(type, data) do
    :ELDAPv3a.encode(type, data)
  end


  def decode(type, data) do
    :ELDAPv3a.decode(type, data)
  end

end
