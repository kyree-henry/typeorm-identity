var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
import { IdentityUser } from 'typeorm-identity/domain';
import { Column, Entity } from 'typeorm';
export var UserType;
(function (UserType) {
    UserType["Admin"] = "Admin";
    UserType["User"] = "User";
    UserType["Guest"] = "Guest";
})(UserType || (UserType = {}));
let ApplicationUser = class ApplicationUser extends IdentityUser {
    gender;
    type;
};
__decorate([
    Column({ nullable: true }),
    __metadata("design:type", String)
], ApplicationUser.prototype, "gender", void 0);
__decorate([
    Column({
        type: 'enum',
        enum: UserType,
        default: UserType.User,
    }),
    __metadata("design:type", String)
], ApplicationUser.prototype, "type", void 0);
ApplicationUser = __decorate([
    Entity()
], ApplicationUser);
export { ApplicationUser };
//# sourceMappingURL=user.entity.js.map