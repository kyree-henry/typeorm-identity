import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: 'UserToken', schema: 'identity' })
export class IdentityUserToken {
    
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column()
    userId: string;

    @Column()
    loginProvider: string;
    
    @Column()
    name: string;

    @Column()
    value: string;
}