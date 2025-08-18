import 'express';

declare module 'express-serve-static-core' {
  interface Request {
    user?: {
      sub: number; // user id
      phone: string;
      type: number;
    };
  }
}
