import { MigrationInterface, QueryRunner } from "typeorm";

export class CreateSubscribersTable1753811713309 implements MigrationInterface {
    name = 'CreateSubscribersTable1753811713309'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "subscribers" ("sid" SERIAL NOT NULL, "sapikey" character varying NOT NULL, "sfname" character varying NOT NULL, "slname" character varying NOT NULL, "semail" character varying NOT NULL, "sphone" character varying NOT NULL, "spass" character varying NOT NULL, "sstate" character varying NOT NULL, "spin" integer NOT NULL, "snewpin" character varying NOT NULL DEFAULT '', "spinstatus" smallint NOT NULL, "stype" smallint NOT NULL, "swallet" double precision NOT NULL, "srefwallet" double precision NOT NULL, "sbankno" character varying NOT NULL, "srolexbank" character varying NOT NULL, "ssterlingbank" character varying NOT NULL, "sfidelitybank" character varying NOT NULL, "skudabank" character varying NOT NULL, "sgtbank" character varying NOT NULL, "sbankname" character varying NOT NULL, "sregstatus" smallint NOT NULL, "svercode" smallint, "sregdate" TIMESTAMP NOT NULL, "slastactivity" TIMESTAMP, "svercode_type" character varying(30), "sreferal" character varying NOT NULL, "sbvn" character varying NOT NULL, "snin" character varying NOT NULL, "sdob" character varying NOT NULL, "skycstatus" character varying NOT NULL, "accountreference" character varying NOT NULL, "spayvesselbank" character varying NOT NULL, "spaymentpoint" character varying NOT NULL, "srefstatus" character varying NOT NULL, "slastip" character varying NOT NULL, "lip" character varying NOT NULL, "rip" character varying NOT NULL, "group_id" character varying NOT NULL, "email_sent" boolean NOT NULL, "saccountlimit" character varying NOT NULL, CONSTRAINT "PK_16d02a309dc1d3c53c4c5d1971a" PRIMARY KEY ("sid"))`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP TABLE "subscribers"`);
    }

}
