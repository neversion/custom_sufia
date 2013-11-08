require 'spec_helper'

describe "multimedia/index" do
  before(:each) do
    assign(:multimedia, [
      stub_model(Multimedium),
      stub_model(Multimedium)
    ])
  end

  it "renders a list of multimedia" do
    render
    # Run the generator again with the --webrat flag if you want to use webrat matchers
  end
end
