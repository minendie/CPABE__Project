IF NOT EXISTS 
   (
     SELECT name FROM master.dbo.sysdatabases 
     WHERE name = 'crypto_db'
    )
CREATE DATABASE crypto_db;
GO

USE crypto_db;
GO

DROP TABLE IF EXISTS Bank;
CREATE TABLE Bank (
  BANKID varchar(10) NOT NULL,
  BANKNAME varchar(100) NOT NULL,
  BANKADDR varchar(100) NOT NULL,
  PRIMARY KEY (BANKID)
);

DROP TABLE IF EXISTS Customer;
CREATE TABLE Customer (
  CUSID varchar(10) NOT NULL,
  CUSNAME varchar(100) NOT NULL,
  SEX varchar(10) NOT NULL,
  DATEOFBIRTH DATE NOT NULL,
  SOCIALID varchar(20) NOT NULL,
  EMAIL varchar(100) NOT NULL,
  ADDRESS varchar(100) NOT NULL,
  PRIMARY KEY (CUSID)
);

DROP TABLE  if exists Branch;
CREATE TABLE Branch (
  BRANCHID varchar(10) NOT NULL,
  BRANCHNAME varchar(100) NOT NULL,
  ADDRESS varchar(100) NOT NULL,
  BANKID varchar(10) NOT NULL,
  PRIMARY KEY (BRANCHID),
 -- FOREIGN KEY (BANKID) REFERENCES `Bank` (`BANKID`)
);

ALTER TABLE Branch ADD CONSTRAINT FK_Bra_Ba FOREIGN KEY (BANKID) REFERENCES Bank (BANKID);

DROP TABLE  if exists Account;
CREATE TABLE Account (
  ACCID varchar(10) NOT NULL,
  ACCUSERNAME varchar(100) NOT NULL,
  ACCPASSWORD varchar(100) NOT NULL,
  DATEOPEN DATE NOT NULL,
  TOTALMONEY DECIMAL(12,2)  NOT NULL,
  DVT varchar(5) NOT NULL,
  CUSID varchar(10) NOT NULL,
  BRANCHID varchar(10) NOT NULL,
  PRIMARY KEY (ACCID),
  
 -- FOREIGN KEY (`CUSID`) REFERENCES `Customer` (`CUSID`),
 -- FOREIGN KEY (`BRANCHID`) REFERENCES `Branch` (`BRANCHID`)
);

ALTER TABLE Account ADD CONSTRAINT FK_Acc_Cus FOREIGN KEY (CUSID) REFERENCES Customer(CUSID) ;
ALTER TABLE Account ADD CONSTRAINT FK_Acc_Bank FOREIGN KEY (BRANCHID) REFERENCES Branch (BRANCHID);


DROP TABLE  if exists Card;
CREATE TABLE Card (
  CARDID varchar(10) NOT NULL,
  STARTDATE DATE NOT NULL,
  EXPIREDDATE DATE NOT NULL,
  TYPECARD varchar(50) NOT NULL,
  CUSID varchar(10) NOT NULL,
  ACCID varchar(10) NOT NULL,
  BRANCHID varchar(10) NOT NULL,
  PRIMARY KEY (CARDID),
  --FOREIGN KEY (CUSID) REFERENCES `Customer` (`CUSID`),
  --FOREIGN KEY (`ACCID`) REFERENCES `Account` (`ACCID`),
  --FOREIGN KEY (`BRANCHID`) REFERENCES `Branch` (`BRANCHID`)
);

ALTER TABLE Card ADD CONSTRAINT FK_Card_Cus FOREIGN KEY (CUSID) REFERENCES Customer (CUSID);
ALTER TABLE Card ADD CONSTRAINT FK_Card_Acc FOREIGN KEY (ACCID) REFERENCES Account (ACCID);
ALTER TABLE Card ADD CONSTRAINT FK_Card_Bra FOREIGN KEY (BRANCHID) REFERENCES Branch (BRANCHID);

DROP TABLE if exists TransactionLog;
CREATE TABLE TransactionLog(
	TRANSID varchar(10) NOT NULL ,
	CARDID varchar(10) NOT NULL,
	MONEY_TRANS decimal(12,2) NOT NULL,
    MONEY_BALANCE decimal(12,2) NOT NULL,
    CONTENT_TRANS varchar(100) ,
    RECV_BANK varchar (10) NOT NULL,
    RECV_ACC varchar (10) NOT NULL,
    DATE_TRANS date	 NOT NULL,
    TIME_TRANS time NOT NULL,
    DVT varchar(5) NOT NULL,
	PRIMARY KEY (TRANSID),
	--foreign key  (`CARDID`) references Card(`CARDID`),
    --foreign key  (`RECV_ACC`) references Account(`ACCID`),
    --foreign key(`RECV_BANK`) references Bank (`BANKID`)    
    
);
ALTER TABLE TransactionLog ADD CONSTRAINT FK_Trans_Card_Card FOREIGN KEY (CARDID) REFERENCES Card(CARDID);
ALTER TABLE TransactionLog ADD CONSTRAINT FK_Trans_Card_Acc FOREIGN KEY (RECV_ACC) REFERENCES Account (ACCID);
ALTER TABLE TransactionLog ADD CONSTRAINT FK_Trans_Bank FOREIGN KEY (RECV_BANK) REFERENCES Bank (BANKID);

--select * from Bank;
--select * from Customer;
--select * from Branch;
--select * from Account;
--select * from Card;
--select * from TransactionLog;