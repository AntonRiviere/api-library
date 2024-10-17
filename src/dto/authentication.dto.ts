export interface AuthenticationInputDTO {
    grant_type: string;
    username: string;
    password: string;
}
  
export interface AuthenticationOutputDTO {
    message: string;
    token?: string;
}