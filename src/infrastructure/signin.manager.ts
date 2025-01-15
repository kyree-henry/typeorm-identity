import { IdentityUser, UserManager } from "index";
import { Service } from "typedi"

@Service()
export class SignInManager<TUser extends IdentityUser<number | string>> {

    constructor(
            private readonly userManager: UserManager<TUser>,
    ) { }
    
 
}