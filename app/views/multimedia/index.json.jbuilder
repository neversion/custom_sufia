json.array!(@multimedia) do |multimedium|
  json.extract! multimedium, 
  json.url multimedium_url(multimedium, format: :json)
end
