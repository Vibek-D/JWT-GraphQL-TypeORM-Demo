import { User } from "./entity/User";
import { sign } from "jsonwebtoken";

//after the user is successfully logged in, ther server sends the user with the acces token which the user can use in the subsequent api calls
export const createAccessToken = (user: User) => {
  return sign({ userId: user.id }, process.env.ACCESS_TOKEN_SECRET!, {
    expiresIn: "15m"
  });
};

//the refresh token is mainly first signed with the user details and a secret key and stored in a cookie and sent in the response from the server
export const createRefreshToken = (user: User) => {
  return sign(
    { userId: user.id, tokenVersion: user.tokenVersion },
    process.env.REFRESH_TOKEN_SECRET!,
    {
      expiresIn: "7d"
    }
  );
};
