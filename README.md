go get github.com/dgrijalva/jwt-go
go get github.com/joho/godotenv
go get github.com/julienschmidt/httprouter


Login :
  request :
  curl -X POST -d "username=admin&password=password" http://localhost:8080/login

  response :
  {"token":"<jwt_token>"}


Protected endpoint :
  request :
  curl -H "Authorization: <jwt_token>" http://localhost:8080/protected

  response :
  {"message":"This is a protected route"}
