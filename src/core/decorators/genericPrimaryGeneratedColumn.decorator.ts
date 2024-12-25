import { PrimaryGeneratedColumn } from "typeorm";

export function GenericPrimaryGeneratedColumn(
  type: "increment" | "uuid"
): PropertyDecorator {
  if (type === "uuid") {
    return PrimaryGeneratedColumn("uuid")
  } else {
    return PrimaryGeneratedColumn("increment")
  }
}