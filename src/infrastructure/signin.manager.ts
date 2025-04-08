import { IdentityUser } from "domain/index";
import { UserManager } from "infrastructure/index";
import { injectable } from "inversify";

@injectable()
export class SignInManager<TUser extends IdentityUser<number | string>> {

    constructor(
            private readonly userManager: UserManager<TUser>,
    ) { }
    
 
}