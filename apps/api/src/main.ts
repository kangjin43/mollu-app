import 'dotenv/config';
import { BadRequestException, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';

async function bootstrap() {
  console.log('DATABASE_URL in Nest:', process.env.DATABASE_URL);

  const app = await NestFactory.create(AppModule);

  app.setGlobalPrefix('api');
  app.useGlobalFilters(new HttpExceptionFilter());

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
      exceptionFactory: (errors) =>
        new BadRequestException({
          message: 'Validation failed.',
          code: 'VALIDATION_ERROR',
          details: errors.map((error) => ({
            field: error.property,
            constraints: error.constraints,
          })),
        }),
    }),
  );

  app.use(cookieParser());

  app.enableCors({
    origin: (process.env.CORS_ORIGIN ??
      'http://localhost:3000,http://localhost:5173,http://localhost:19006')
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean),
    credentials: true,
  });

  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const config = new DocumentBuilder()
      .setTitle('Mollu API')
      .setDescription('API documentation')
      .setVersion('1.0')
      .addBearerAuth()
      .addCookieAuth('refresh_token')
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document);
  }

  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);
}

bootstrap();
