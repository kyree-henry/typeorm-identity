import { GenericPrimaryGeneratedColumn } from 'core/decorators/genericPrimaryGeneratedColumn.decorator';
import { IdentityRoleClaim } from './roleClaim.entity';
import { Entity, Column, OneToMany } from 'typeorm';

@Entity({ name: 'Roles', schema: 'identity' })
export class IdentityRole<T> {

    @GenericPrimaryGeneratedColumn(typeof this === "string" ? "uuid" : "increment")
    id: T;

    @Column()
    name: string;

    @Column()
    description?: string;

    @Column()
    normalizedName: string;

    @Column({ default: false })
    isDisabled: boolean;

    @Column({ type: 'timestamp', nullable: true })
    disabledUntil?: Date;

    @OneToMany(() => IdentityRoleClaim, roleClaims => roleClaims.role)
    roleClaims: IdentityRoleClaim[];

    constructor(request: Partial<IdentityRole<T>> = {}) {
        Object.assign(this, request);
        this.normalizedName = request.name?.normalize("NFC");
    }
} 