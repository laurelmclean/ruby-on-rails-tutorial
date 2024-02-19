require "test_helper"

class UsersSignupTest < ActionDispatch::IntegrationTest
  test "invalid sign up information" do
    get signup_path
    assert_no_difference 'User.count' do
      post users_path, params: { user: {name: "", email: "user@invalid", password: "foo", password_confirmation: "bar"}}
    end
    assert_response :unprocessable_entity
    assert_template 'users/new'
  end

    test "valid sign up information" do
    get signup_path
    assert_difference 'User.count', 1 do
      post users_path, params: { user: {name: "Example", email: "user@example.com", password: "foo123", password_confirmation: "foo123"}}
    end
    follow_redirect!
    assert_template 'users/show'
    assert_not flash.empty?
  end
end
