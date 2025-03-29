export class InvalidLoginError extends Error {
  constructor(message = "Invalid login credentials") {
    super(message);
    this.name = "InvalidLoginError";
  }
}
