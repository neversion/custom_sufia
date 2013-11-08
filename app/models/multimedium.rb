class Multimedium < ActiveFedora::Base
  include Sufia::GenericFile

  has_metadata :name => "customMetadata", :type => CustomDatastream
  delegate :subtitle, to: 'customMetadata'
  delegate :keyword, to: 'customMetadata'
  delegate :set_number, to: 'customMetadata'
  delegate :call_number, to: 'customMetadata'
  delegate :class1, to: 'customMetadata'
  delegate :class2, to: 'customMetadata'
  delegate :format_number, to: 'customMetadata'
  delegate :media_format, to: 'customMetadata'
  delegate :becount, to: 'customMetadata'
  delegate :publish_date, to: 'customMetadata'
  delegate :app_format, to: 'customMetadata'
  delegate :cover_pic, to: 'customMetadata'
  delegate :the_time, to: 'customMetadata'
  delegate :data_stamp, to: 'customMetadata'

end
