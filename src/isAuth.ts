import { MiddlewareFn } from "type-graphql";
import { verify } from "jsonwebtoken";
import { MyContext } from "./myContext";

//this ia a middleware resolver that runs before every resolver and validates the access token and only then runs the resolver function and the next() on line 25 calls next middleware
//which is actually the resolver function
export const isAuth: MiddlewareFn<MyContext> = ({ context }, next) => {
//note that the middleware has access to the context parameter send from the userResolver.ts line 38
  const authorization = context.req.headers["authorization"];

  if (!authorization) {
    throw new Error("Not authenticated");
  }

  try {
  //the authorization header is 'bearer [access token]' and we split it and take only the access token
    const token = authorization.split(" ")[1];
  //the verify() verifies the access token, depending on if its valid with the access token secret and also if its expired and return a payload about the user details that we passed in
  //auth.ts line 6 to sign the access token when the user first logs in
    const payload = verify(token, process.env.ACCESS_TOKEN_SECRET!);
  //middleware also attaches the payload to the context so that the next resolver can use it
    context.payload = payload as any;
  } catch (err) {
    console.log(err);
    throw new Error("Not authenticated");
  }

  return next();
};
