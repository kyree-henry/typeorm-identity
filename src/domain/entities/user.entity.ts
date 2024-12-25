import { GenericPrimaryGeneratedColumn } from 'core/decorators/genericPrimaryGeneratedColumn.decorator';
import { generateTimestampUUID } from 'core/utils/security.util';
import { Entity, Column } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';

@Entity()
export class IdentityUser<T> {

    @GenericPrimaryGeneratedColumn(typeof this === "string" ? "uuid" : "increment")
    id: T;

    @Column({ default: true })
    isActive?: boolean;

    @Column({ type: 'timestamp', nullable: true })
    registeredOn: Date;

    @Column({ nullable: true })
    userName?: string;

    @Column({ nullable: true })
    normalizedUserName?: string;

    @Column({ nullable: true })
    normalizedEmail?: string;

    @Column({ default: false })
    emailConfirmed: boolean;

    @Column({ nullable: true })
    phoneNumber?: string;

    @Column({ default: false })
    phoneNumberConfirmed!: boolean;

    @Column({ default: false })
    twoFactorEnabled!: boolean;

    @Column({ type: 'timestamp', nullable: true })
    lockoutEnd?: Date;

    @Column({ default: 0 })
    accessFailedCount: number;

    @Column({ default: false })
    lockoutEnabled: boolean;

    @Column()
    email: string;

    @Column()
    concurrencyStamp: string;

    @Column({ nullable: true })
    securityStamp: string;

    @Column({ nullable: true })
    passwordHash?: string;

    constructor(request: Partial<IdentityUser<T>> = {}) {
        Object.assign(this, request);
        this.normalizedEmail = this.email?.normalize("NFC");
        this.registeredOn = new Date();
        this.concurrencyStamp = generateTimestampUUID();
    }
}