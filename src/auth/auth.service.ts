import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from "argon2";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import { JwtPayload, Token } from "./types";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService) {}

    async register(authDto: AuthDto): Promise<Token> {
        const password = await this.hashPassword(authDto.password);

        try {
            const newUser = await this.prisma.user.create({
                data: {
                    email: authDto.email,
                    password,
                    firstName: authDto.firstName,
                    lastName: authDto.lastName
                }
            });

            return this.getToken(newUser.id, newUser.email);
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError || error.code === "P2002") {
                throw new ForbiddenException("User credentials are taken");
            }
        }
    }

    async login(authDto: AuthDto): Promise<Token> {
        const user = await this.prisma.user.findUnique({
            where: {
                email: authDto.email
            }
        });

        if (!user) {
            throw new ForbiddenException("Access denied, email doesn't match");
        }

        const passwordMatch = await argon.verify(user.password, authDto.password);
        if (!passwordMatch) {
            throw new ForbiddenException("Access denied, password doesn't match.");
        }

        return this.getToken(user.id, user.email);
    }

    hashPassword(password: string) {
        return argon.hash(password);
    }

    async getToken(userId: number, email: string): Promise<Token> {
        const payload: JwtPayload = {
            sub: userId,
            email
        };

        const [accessToken] = await Promise.all([
            this.jwt.signAsync(payload, {
                secret: process.env.JWT_SECRET,
                expiresIn: 60 * 5
            })
        ]);

        return {
            access_token: accessToken
        };
    }
}
