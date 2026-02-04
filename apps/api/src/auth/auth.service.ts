import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { randomUUID } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { UsersService } from '../users/users.service';
import {
  DEFAULT_ACCESS_TOKEN_TTL,
  DEFAULT_REFRESH_TOKEN_TTL,
} from './auth.constants';
import { hashToken, durationToMs } from './utils/token-utils';

interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async signup(email: string, password: string) {
    const user = await this.usersService.createUser(email, password);
    return this.sanitizeUser(user);
  }

  async login(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException({
        message: 'Invalid credentials.',
        code: 'AUTH_INVALID_CREDENTIALS',
      });
    }

    const matches = await bcrypt.compare(password, user.passwordHash);
    if (!matches) {
      throw new UnauthorizedException({
        message: 'Invalid credentials.',
        code: 'AUTH_INVALID_CREDENTIALS',
      });
    }

    const tokens = await this.issueTokens(user.id, user.email);
    await this.storeRefreshToken(user.id, tokens.refreshToken);
    return {
      user: this.sanitizeUser(user),
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async refresh(refreshToken: string) {
    if (!refreshToken) {
      throw new UnauthorizedException({
        message: 'Refresh token is missing.',
        code: 'AUTH_REFRESH_MISSING',
      });
    }

    const payload = await this.verifyRefreshToken(refreshToken);
    const tokenHash = hashToken(refreshToken);

    const storedToken = await this.prisma.refreshToken.findFirst({
      where: {
        jti: payload.jti,
        userId: payload.sub,
        tokenHash,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
    });

    if (!storedToken) {
      throw new UnauthorizedException({
        message: 'Refresh token is invalid.',
        code: 'AUTH_REFRESH_INVALID',
      });
    }

    await this.prisma.refreshToken.update({
      where: { id: storedToken.id },
      data: { revokedAt: new Date() },
    });

    const tokens = await this.issueTokens(payload.sub, payload.email);
    await this.storeRefreshToken(payload.sub, tokens.refreshToken);
    return { accessToken: tokens.accessToken, refreshToken: tokens.refreshToken };
  }

  async logout(refreshToken: string) {
    if (!refreshToken) {
      return;
    }

    try {
      const payload = await this.verifyRefreshToken(refreshToken);
      await this.prisma.refreshToken.updateMany({
        where: {
          jti: payload.jti,
          userId: payload.sub,
          revokedAt: null,
        },
        data: { revokedAt: new Date() },
      });
    } catch {
      return;
    }
  }

  private async issueTokens(userId: string, email: string): Promise<TokenPair> {
    const accessToken = await this.jwtService.signAsync(
      { sub: userId, email },
      {
        secret: process.env.JWT_ACCESS_SECRET ?? 'dev-access-secret',
        expiresIn:
          process.env.JWT_ACCESS_EXPIRES_IN ?? DEFAULT_ACCESS_TOKEN_TTL,
      },
    );

    const refreshToken = await this.jwtService.signAsync(
      { sub: userId, email, jti: randomUUID(), typ: 'refresh' },
      {
        secret: process.env.JWT_REFRESH_SECRET ?? 'dev-refresh-secret',
        expiresIn:
          process.env.JWT_REFRESH_EXPIRES_IN ?? DEFAULT_REFRESH_TOKEN_TTL,
      },
    );

    return { accessToken, refreshToken };
  }

  private async storeRefreshToken(userId: string, refreshToken: string) {
    const payload = this.jwtService.decode(refreshToken) as {
      jti?: string;
      exp?: number;
    };
    if (!payload?.jti || !payload.exp) {
      throw new UnauthorizedException({
        message: 'Refresh token is invalid.',
        code: 'AUTH_REFRESH_INVALID',
      });
    }

    const expiresAt = new Date(payload.exp * 1000);

    await this.prisma.refreshToken.create({
      data: {
        userId,
        tokenHash: hashToken(refreshToken),
        jti: payload.jti,
        expiresAt,
      },
    });
  }

  private async verifyRefreshToken(refreshToken: string) {
    try {
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET ?? 'dev-refresh-secret',
      });

      if (payload?.typ !== 'refresh') {
        throw new UnauthorizedException({
          message: 'Refresh token is invalid.',
          code: 'AUTH_REFRESH_INVALID',
        });
      }

      return payload as { sub: string; email: string; jti: string; typ: string };
    } catch {
      throw new UnauthorizedException({
        message: 'Refresh token is invalid.',
        code: 'AUTH_REFRESH_INVALID',
      });
    }
  }

  getRefreshTokenTtlMs() {
    return durationToMs(
      process.env.JWT_REFRESH_EXPIRES_IN ?? DEFAULT_REFRESH_TOKEN_TTL,
      7 * 24 * 60 * 60 * 1000,
    );
  }

  sanitizeUser(user: { id: string; email: string; nickname?: string | null }) {
    return {
      id: user.id,
      email: user.email,
      nickname: user.nickname ?? null,
    };
  }
}
