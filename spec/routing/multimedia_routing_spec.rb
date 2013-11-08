require "spec_helper"

describe MultimediaController do
  describe "routing" do

    it "routes to #index" do
      get("/multimedia").should route_to("multimedia#index")
    end

    it "routes to #new" do
      get("/multimedia/new").should route_to("multimedia#new")
    end

    it "routes to #show" do
      get("/multimedia/1").should route_to("multimedia#show", :id => "1")
    end

    it "routes to #edit" do
      get("/multimedia/1/edit").should route_to("multimedia#edit", :id => "1")
    end

    it "routes to #create" do
      post("/multimedia").should route_to("multimedia#create")
    end

    it "routes to #update" do
      put("/multimedia/1").should route_to("multimedia#update", :id => "1")
    end

    it "routes to #destroy" do
      delete("/multimedia/1").should route_to("multimedia#destroy", :id => "1")
    end

  end
end
