import { Column, Entity } from 'typeorm';
import { IdentityRole } from 'typeorm-identity/domain';

export enum RoleType {
    System = 'System',
    Custom = 'Custom'
}

@Entity()
export class AppRole extends IdentityRole<string> {
    @Column({
        type: 'varchar',
        enum: RoleType,
        default: RoleType.Custom
    })
    roleType: RoleType;
    
    @Column({ nullable: true })
    description?: string;
} 