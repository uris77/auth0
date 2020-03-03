# Auth0 Golang Authorizer

An Auth0 client written in Go for writing AWS Lambda Authorizers. It is heavily based on [github.com/apibillme/auth0](github.com/apibillme/auth0).
The main change in this fork is that the validating function accepts a string instead of an http request. Since API Gateway
provides the token as a string, it was a bit gnarly to be using the http request as the function's input.

## Usage

[Simple Overview of how the client works](https://dev.to/uris77/go-notes-auth0-validation-for-aws-lambda-2i24)
[Example of how to write a lambda authorizer with this Auth0 client](https://dev.to/uris77/go-notes-auth0-validation-for-aws-lambda-pt-2-36d3).

