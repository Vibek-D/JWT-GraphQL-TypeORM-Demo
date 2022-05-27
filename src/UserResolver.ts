import {
  Resolver,
  Query,
  Mutation,
  Arg,
  ObjectType,
  Field,
  Ctx,
  UseMiddleware,
  Int
} from "type-graphql";
import { hash, compare } from "bcryptjs";
import { User } from "./entity/User";
import { MyContext } from "./myContext";
import { createRefreshToken, createAccessToken } from "./auth";
import { isAuth } from "./isAuth";
import { sendRefreshToken } from "./sendRefreshToken";
import { getConnection } from "typeorm";
import { verify } from "jsonwebtoken";

//this is how we create a graphql type from the type-graphql library
@ObjectType()
class LoginResponse {
  @Field()
  accessToken: string;
  @Field(() => User)
  user: User;
}

@Resolver()
//since we are passing the context({req, res}) from /index.ts line 64, we have access to it in all the resolvers in here
export class UserResolver {
  @Query(() => String)
  hello() {
    return "Hi!";
  }

  @Query(() => String)
  //middleware that runs before the actual bye() resolver to check if the user is authenticated using the access token, check isAuth.ts, , also passed down the context parameter
  @UseMiddleware(isAuth)
  //here the middleware has attached the payload after authenticating it and we are taking the userId from it, check isAuth line 22
  bye(@Ctx() { payload }: MyContext) {
  //in the @Ctx() { payload } we are getting the payload that the middleware returned to the next resolver
    console.log(payload);
    return `Your user id is: ${payload!.userId}`;
  }

  @Query(() => [User])
  users() {
    return User.find();
  }

  @Query(() => User, { nullable: true })
  //here we are accessing the req object that we were passing from /index.ts line 64
  me(@Ctx() context: MyContext) {
    const authorization = context.req.headers["authorization"];

    if (!authorization) {
      return null;
    }

    try {
      const token = authorization.split(" ")[1];
      const payload: any = verify(token, process.env.ACCESS_TOKEN_SECRET!);
      return User.findOne(payload.userId);
    } catch (err) {
      console.log(err);
      return null;
    }
  }

  @Mutation(() => Boolean)
  async logout(@Ctx() { res }: MyContext) {
    sendRefreshToken(res, "");

    return true;
  }

  @Mutation(() => Boolean)
  async revokeRefreshTokensForUser(@Arg("userId", () => Int) userId: number) {
    await getConnection()
      .getRepository(User)
      .increment({ id: userId }, "tokenVersion", 1);

    return true;
  }

  //here () => LoginResponse is the return type of the mutation and thats how we define the return type by an arrow function
  @Mutation(() => LoginResponse)
  async login(
    @Arg("email") email: string,
    @Arg("password") password: string,
    @Ctx() { res }: MyContext
  ): Promise<LoginResponse> {
  //here it means that email and passowrd are @Arg ie arguments and @Ctx ie context and here we are accessing the res parameter that we were passing from /index.ts line 64
    const user = await User.findOne({ where: { email } });

    if (!user) {
      throw new Error("Could not find user");
    }

    const valid = await compare(password, user.password);

    if (!valid) {
      throw new Error("Bad password");
    }

    // login successful

    //creating the refresh token and then attachig=ng the token in the cookie of the response
    sendRefreshToken(res, createRefreshToken(user));

    return {
      accessToken: createAccessToken(user),
      user
    };
  }

  @Mutation(() => Boolean)
  async register(
    @Arg("email") email: string,
    @Arg("password") password: string
  ) {
    const hashedPassword = await hash(password, 12);

    try {
      await User.insert({
        email,
        password: hashedPassword
      });
    } catch (err) {
      console.log(err);
      return false;
    }

    return true;
  }
}
