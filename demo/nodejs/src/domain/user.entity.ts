import { IdentityUser } from 'typeorm-identity/domain';
import { Column, Entity } from 'typeorm';

export enum UserType {
    Admin = 'Admin',
    User = 'User',
    Guest = 'Guest',
}

@Entity()
export class ApplicationUser extends IdentityUser<number> {
    
    @Column({ nullable: true })
    gender?: string;
    
    @Column({
        type: 'enum',
        enum: UserType,
        default: UserType.User,
    })
    type: UserType;
}