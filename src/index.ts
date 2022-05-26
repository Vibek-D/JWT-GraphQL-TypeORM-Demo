import "dotenv/config";
import cors from "cors";
import "reflect-metadata";
import express from "express";
import { ApolloServer } from "apollo-server-express";
import { buildSchema } from "type-graphql";
import { UserResolver } from "./userResolver";
import { createConnection } from "typeorm";
import cookieParser from "cookie-parser";
import { verify } from "jsonwebtoken";
import { User } from "./entity/User";
import { sendRefreshToken } from "./sendRefreshToken";
import { createAccessToken, createRefreshToken } from "./auth";

(async () => {
  const app = express();
  app.use(
    cors({
      origin: "http://localhost:3000",
      credentials: true
    })
  );
  app.use(cookieParser());
  app.get("/", (_req: any, res: any) => res.send("Server pinged"));
  app.post("/refreshToken", async (req: any, res: any) => {
    const token = req.cookies.jid;
    if (!token) {
      return res.send({ ok: false, accessToken: "" });
    }

    let payload: any = null;
    try {
      payload = verify(token, process.env.REFRESH_TOKEN_SECRET!);
    } catch (err) {
      console.log(err);
      return res.send({ ok: false, accessToken: "" });
    }

    // token is valid and we can send back an access token
    const user = await User.findOne({ id: payload.userId });

    if (!user) {
      return res.send({ ok: false, accessToken: "" });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.send({ ok: false, accessToken: "" });
    }

    sendRefreshToken(res, createRefreshToken(user));

    return res.send({ ok: true, accessToken: createAccessToken(user) });
  });

  await createConnection();

  //building the apollo server where we have to build the server by passing the list of different resolvers (mainly separated by the different tables/entities, different tables should
  // have different resolvers)  
  const apolloServer = new ApolloServer({
    schema: await buildSchema({
      resolvers: [UserResolver]
    }),
  //here we are passing the the request and response object to all the resolver functions on the above resolver parameter via the context()
    context: ({ req, res }: any) => ({ req, res })
  });

  apolloServer.applyMiddleware({ app, cors: false });

  app.listen(4000, () => {
    console.log("Server started");
  });
})();
