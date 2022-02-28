import { Controller, Post, Body, HttpStatus, HttpCode } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthDto } from "./dto";

@Controller("api/auth")
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @HttpCode(HttpStatus.CREATED)
    @Post("register")
    register(@Body() authDto: AuthDto) {
        return this.authService.register(authDto);
    }

    @HttpCode(HttpStatus.OK)
    @Post("login")
    login(@Body() authDto: AuthDto) {
        return this.authService.login(authDto);
    }
}
