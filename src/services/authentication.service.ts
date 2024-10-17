import { User } from "../models/user.model"; // Modèle Sequelize
import jwt from "jsonwebtoken"; // Pour générer le JWT
import { Buffer } from "buffer"; // Pour décoder Base64
import { notFound } from "../error/NotFoundError";

const JWT_SECRET = process.env.JWT_SECRET || "toto"; // Clé secrète pour signer le token

const permissions = {
  admin: {
    author: ['read', 'write', 'delete'],
    book: ['read', 'write', 'delete'],
    bookCollection: ['read', 'write', 'delete']
  },
  gerant: {
    author: ['read', 'write'],
    book: ['read', 'write'],
    bookCollection: ['read', 'write', 'delete']
  },
  utilisateur: {
    author: ['read'],
    book: ['read', 'write'],
    bookCollection: ['read']
  }
};

export class AuthenticationService {
  public async authenticate(
    username: string,
    password: string
  ): Promise<string> {
    // Recherche l'utilisateur dans la base de données
    const user = await User.findOne({ where: { username } });

    if (!user) {
      throw notFound("User");
    }

    // Décoder le mot de passe stocké en base de données
    const decodedPassword = Buffer.from(user.password, "base64").toString(
      "utf-8"
    );

    // Vérifie si le mot de passe est correct
    if (password === decodedPassword) {
      

      let userPermissions = {};
      if(username === "admin"){
        userPermissions = permissions["admin"] || {};
      }
      if(username === "gerant"){
        userPermissions = permissions["gerant"] || {};
      }
      if(username === "utilisateur"){
        userPermissions = permissions["utilisateur"] || {};
      }
      
      // Si l'utilisateur est authentifié, on génère un JWT avec les permissions
      const token = jwt.sign(
        { username: user.username, scopes: userPermissions },
        JWT_SECRET,
        { expiresIn: "1h" }
      );
      return token;
    } else {
      let error = new Error("Wrong password");
      (error as any).status = 403;
      throw error;
    }
  }
}

export const authService = new AuthenticationService();