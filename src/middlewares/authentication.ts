import * as express from "express";
import * as jwt from "jsonwebtoken";

export function expressAuthentication(
  request: express.Request,
  securityName: string,
  scopes?: string[]
): Promise<any> {
  if (securityName === "jwt") {
    const token =
      request.body.token ||
      request.query.token ||
      request.headers["authorization"]?.split(' ')[1];

    return new Promise((resolve, reject) => {
      if (!token) {
        reject(new Error("No token provided"));
      }
      jwt.verify(
        token,
        "toto",
        function (err: any, decoded: any) {
          if (err) {
            reject(err);
          } else {
            if (scopes !== undefined) {
              // Check if JWT contains all required scopes
              if (!decoded.scopes || typeof decoded.scopes !== 'object') {
                reject(new Error("JWT does not contain any scopes."));
              }
              const userScopes = decoded.scopes;
              for (let scope of scopes) {
                const [resource, action] = scope.split(":");
                if (!userScopes[resource]?.includes(action)) {
                  reject(new Error(`JWT does not contain required permission for ${scope}`));
                }
              }
            }
            resolve(decoded);
          }
        }
      );
    });
  } else {
    throw new Error("Only support JWT securityName");
  }
}
//si cette ligne apparait sur git alors c'est la dernière version