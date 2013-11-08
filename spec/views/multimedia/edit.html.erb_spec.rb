require 'spec_helper'

describe "multimedia/edit" do
  before(:each) do
    @multimedium = assign(:multimedium, stub_model(Multimedium))
  end

  it "renders the edit multimedium form" do
    render

    # Run the generator again with the --webrat flag if you want to use webrat matchers
    assert_select "form[action=?][method=?]", multimedium_path(@multimedium), "post" do
    end
  end
end
