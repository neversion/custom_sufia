require 'spec_helper'

describe "multimedia/new" do
  before(:each) do
    assign(:multimedium, stub_model(Multimedium).as_new_record)
  end

  it "renders new multimedium form" do
    render

    # Run the generator again with the --webrat flag if you want to use webrat matchers
    assert_select "form[action=?][method=?]", multimedia_path, "post" do
    end
  end
end
