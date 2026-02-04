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
import { ApiBearerAuth, ApiCookieAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import type { CookieOptions, Request, Response } from 'express';

import { AuthService } from './auth.service';
import { SignupDto } from '../users/dto/signup.dto';
import { LoginDto } from '../users/dto/login.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  private getRefreshCookieOptions(): CookieOptions {
    const isProd = process.env.NODE_ENV === 'production';

    return {
      httpOnly: true,
      secure: isProd, // dev=false, prod=true(HTTPS)
      sameSite: (isProd ? 'none' : 'lax') as CookieOptions['sameSite'],
      path: '/api/auth/refresh', // ✅ refresh 요청에만 쿠키 전송
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7d
    };
  }

  private clearRefreshCookie(res: Response) {
    const opts = this.getRefreshCookieOptions();
    res.clearCookie('refresh_token', {
      httpOnly: opts.httpOnly,
      secure: opts.secure,
      sameSite: opts.sameSite,
      path: opts.path,
    });
  }

  @Post('signup')
  @ApiOperation({ summary: '회원가입' })
  async signup(@Body() body: SignupDto) {
    // AuthService가 nickname을 받는 형태/안 받는 형태 모두 대응
    return (this.authService as any).signup(body.email, body.password, body.nickname);
  }

  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: '로그인 (accessToken + refresh_token 쿠키 설정)' })
  async login(@Body() body: LoginDto, @Res({ passthrough: true }) res: Response) {
    const result = await (this.authService as any).login(body.email, body.password);

    const accessToken: string =
      result?.accessToken ?? result?.access_token ?? result?.token;

    const refreshToken: string | undefined =
      result?.refreshToken ?? result?.refresh_token ?? result?.refresh;

    if (refreshToken) {
      res.cookie('refresh_token', refreshToken, this.getRefreshCookieOptions());
    }

    // accessToken은 기존 방식(헤더) 유지
    res.setHeader('authorization', `Bearer ${accessToken}`);

    // body에도 내려주면 Swagger/프론트 테스트 편함
    return { accessToken };
  }

  @Post('refresh')
  @HttpCode(200)
  @ApiCookieAuth('refresh_token')
  @ApiOperation({ summary: '토큰 재발급 (refresh_token 쿠키 필요)' })
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies?.refresh_token as string | undefined;

    const result = await (this.authService as any).refresh(refreshToken);

    const accessToken: string =
      result?.accessToken ?? result?.access_token ?? result?.token;

    const newRefreshToken: string | undefined =
      result?.refreshToken ?? result?.refresh_token ?? result?.refresh;

    if (newRefreshToken) {
      res.cookie('refresh_token', newRefreshToken, this.getRefreshCookieOptions());
    }

    res.setHeader('authorization', `Bearer ${accessToken}`);
    return { accessToken };
  }

  @Post('logout')
  @HttpCode(200)
  @ApiCookieAuth('refresh_token')
  @ApiOperation({ summary: '로그아웃 (refresh_token 폐기 + 쿠키 삭제)' })
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies?.refresh_token as string | undefined;

    // 서버측 refresh 폐기 로직이 있다면 호출(없어도 try/catch로 안전)
    try {
      await (this.authService as any).logout(refreshToken);
    } catch {}

    this.clearRefreshCookie(res);
    return { ok: true };
  }

  @Get('me')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @ApiOperation({ summary: '내 정보(AccessToken 필요)' })
  async me(@Req() req: Request) {
    return req.user;
  }
}
