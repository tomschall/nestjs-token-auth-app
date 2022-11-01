import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  UseGuards,
  Res,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AccessTokenGuard } from 'src/common/guards/accessToken.guard';
import { RefreshTokenGuard } from 'src/common/guards/refreshToken.guard';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  async signup(
    @Body() createUserDto: CreateUserDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tokens = await this.authService.signUp(createUserDto);
    res.cookie('token', tokens.refreshToken, { httpOnly: true });
    return tokens.accessToken;
  }

  @Post('signin')
  async signin(
    @Body() data: AuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tokens = await this.authService.signIn(data);
    res.cookie('token', tokens.refreshToken, { httpOnly: true });
    return tokens.accessToken;
  }

  @UseGuards(AccessTokenGuard)
  @Get('logout')
  logout(@Req() req: Request) {
    this.authService.logout(req.user['sub']);
  }

  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  async refreshTokens(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    console.log('req.user', req.user);
    const userId = req.user['sub'];
    const refreshToken = req.user['refreshToken'];
    const tokens = await this.authService.refreshTokens(userId, refreshToken);
    res.cookie('token', tokens.refreshToken, { httpOnly: true });
    return tokens.accessToken;
  }

  @UseGuards(AccessTokenGuard)
  @Get('isAuthenticated')
  isAuthenticated(@Req() req: Request) {
    const isAuthenticated = req.isAuthenticated();
    console.log('isAuthenticated', isAuthenticated);
    return isAuthenticated;
  }
}
