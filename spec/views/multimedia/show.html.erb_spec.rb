require 'spec_helper'

describe "multimedia/show" do
  before(:each) do
    @multimedium = assign(:multimedium, stub_model(Multimedium))
  end

  it "renders attributes in <p>" do
    render
    # Run the generator again with the --webrat flag if you want to use webrat matchers
  end
end
