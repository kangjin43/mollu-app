import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCookieAuth,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { AuthService } from './auth.service';
import { LoginDto } from '../users/dto/login.dto';
import { SignupDto } from '../users/dto/signup.dto';
import { UsersService } from '../users/users.service';
import {
  REFRESH_TOKEN_COOKIE_NAME,
  REFRESH_TOKEN_COOKIE_PATH,
} from './auth.constants';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
  ) {}

  @Post('signup')
  @ApiBody({
    type: SignupDto,
    examples: {
      signup: {
        summary: 'Signup',
        value: {
          email: 'user@example.com',
          password: 'password123',
          nickname: 'mollu',
        },
      },
    },
  })
  @ApiResponse({
    status: 201,
    description: 'User created',
    schema: {
      example: { id: 'uuid', email: 'user@example.com', nickname: 'mollu' },
    },
  })
  async signup(@Body() body: SignupDto) {
    return this.authService.signup(body.email, body.password, body.nickname);
  }

  @Post('login')
  @HttpCode(200)
  @ApiBody({
    type: LoginDto,
    examples: {
      login: {
        summary: 'Login',
        value: { email: 'user@example.com', password: 'password123' },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Access token returned and refresh cookie set.',
    schema: {
      example: {
        user: { id: 'uuid', email: 'user@example.com', nickname: null },
        accessToken: 'jwt-access-token',
      },
    },
  })
  async login(
    @Body() body: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { user, accessToken, refreshToken } = await this.authService.login(
      body.email,
      body.password,
    );
    this.setRefreshCookie(res, refreshToken);
    res.setHeader('Authorization', `Bearer ${accessToken}`);
    return { user, accessToken };
  }

  @Post('refresh')
  @HttpCode(200)
  @ApiCookieAuth(REFRESH_TOKEN_COOKIE_NAME)
  @ApiResponse({
    status: 200,
    description: 'Rotate refresh token and return a new access token.',
    schema: {
      example: { accessToken: 'new-jwt-access-token' },
    },
  })
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies?.[REFRESH_TOKEN_COOKIE_NAME];
    const tokens = await this.authService.refresh(refreshToken);
    this.setRefreshCookie(res, tokens.refreshToken);
    res.setHeader('Authorization', `Bearer ${tokens.accessToken}`);
    return { accessToken: tokens.accessToken };
  }

  @Post('logout')
  @HttpCode(200)
  @ApiCookieAuth(REFRESH_TOKEN_COOKIE_NAME)
  @ApiResponse({
    status: 200,
    description: 'Logout and revoke refresh token session.',
    schema: {
      example: { ok: true },
    },
  })
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies?.[REFRESH_TOKEN_COOKIE_NAME];
    await this.authService.logout(refreshToken);
    res.clearCookie(
      REFRESH_TOKEN_COOKIE_NAME,
      this.getRefreshCookieOptions(),
    );
    return { ok: true };
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiResponse({
    status: 200,
    schema: {
      example: { id: 'uuid', email: 'user@example.com', nickname: null },
    },
  })
  async me(@Req() req: Request) {
    const payload = req.user as { sub: string; email: string };
    const user = await this.usersService.findById(payload.sub);
    if (!user) {
      return { id: payload.sub, email: payload.email, nickname: null };
    }
    return this.authService.sanitizeUser(user);
  }

  private setRefreshCookie(res: Response, refreshToken: string) {
    res.cookie(
      REFRESH_TOKEN_COOKIE_NAME,
      refreshToken,
      this.getRefreshCookieOptions(),
    );
  }

  private isProduction() {
    return process.env.NODE_ENV === 'production';
  }

  private getRefreshCookieOptions() {
    const isProd = this.isProduction();
    return {
      httpOnly: true,
      sameSite: isProd ? 'none' : 'lax',
      secure: isProd,
      path: REFRESH_TOKEN_COOKIE_PATH,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    } as const;
  }
}
