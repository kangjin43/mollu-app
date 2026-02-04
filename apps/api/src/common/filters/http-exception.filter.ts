import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionResponse =
      exception instanceof HttpException ? exception.getResponse() : null;

    const body = this.normalizeResponse(exceptionResponse, status);
    response.status(status).json(body);
  }

  private normalizeResponse(
    exceptionResponse: unknown,
    status: number,
  ): { message: string; code: string; details?: unknown } {
    if (!exceptionResponse) {
      return {
        message: 'Internal server error.',
        code: 'INTERNAL_SERVER_ERROR',
      };
    }

    if (typeof exceptionResponse === 'string') {
      return { message: exceptionResponse, code: `HTTP_${status}` };
    }

    if (
      typeof exceptionResponse === 'object' &&
      exceptionResponse !== null &&
      'message' in exceptionResponse
    ) {
      const message = Array.isArray(exceptionResponse['message'])
        ? 'Validation failed.'
        : String(exceptionResponse['message']);
      const code =
        typeof exceptionResponse['code'] === 'string'
          ? exceptionResponse['code']
          : `HTTP_${status}`;
      const details =
        'details' in exceptionResponse ? exceptionResponse['details'] : undefined;
      return { message, code, details };
    }

    return { message: 'Unexpected error.', code: `HTTP_${status}` };
  }
}
