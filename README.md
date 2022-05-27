# JWT-GraphQL-TypeORM-Demo
Securing graphql apis wth jwt access and ref tokens

# Notes
When we create the apollo server using new ApolloServer, we pass the schema where we provide the list of resolvers. Note that to send the (req, res) from express down the chain, 
we have to use the context: ({ req, res }), wheich is then accessable by all the resolvers and middlewares that run prior to the resolvers.

The main job of the middlewares is to validate the req.headers has the auth token, if yes, then decode the token and get the user data from the token and attach the user data payload
to the req.payload, which can be used in the down the chain 'next()' resolvers.