-- MySQL dump 10.11
--
-- Host: localhost    Database: comment
-- ------------------------------------------------------
-- Server version	5.0.45

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `comment`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `comment` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `comment`;

--
-- Table structure for table `Pers`
--

DROP TABLE IF EXISTS `Pers`;
CREATE TABLE `Pers` (
  `Id` int(11) NOT NULL auto_increment,
  `Name` varchar(255) NOT NULL,
  `Pass` varchar(255) NOT NULL,
  PRIMARY KEY  (`Id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `Pers`
--

LOCK TABLES `Pers` WRITE;
/*!40000 ALTER TABLE `Pers` DISABLE KEYS */;
/*!40000 ALTER TABLE `Pers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `com`
--

DROP TABLE IF EXISTS `com`;
CREATE TABLE `com` (
  `comid` int(11) NOT NULL auto_increment,
  `User` varchar(255) NOT NULL,
  `com` text NOT NULL,
  PRIMARY KEY  (`comid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `com`
--

LOCK TABLES `com` WRITE;
/*!40000 ALTER TABLE `com` DISABLE KEYS */;
/*!40000 ALTER TABLE `com` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `comment`
--

DROP TABLE IF EXISTS `comment`;
CREATE TABLE `comment` (
  `commentid` int(11) NOT NULL auto_increment,
  `name` text NOT NULL,
  `comment` text,
  PRIMARY KEY  (`commentid`)
) ENGINE=MyISAM AUTO_INCREMENT=675 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `comment`
--

LOCK TABLES `comment` WRITE;
/*!40000 ALTER TABLE `comment` DISABLE KEYS */;
INSERT INTO `comment` VALUES (674,'MOHIT','Hello');
/*!40000 ALTER TABLE `comment` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cros`
--

DROP TABLE IF EXISTS `cros`;
CREATE TABLE `cros` (
  `ID` int(13) NOT NULL auto_increment,
  `User` varchar(255) NOT NULL,
  `Pass` varchar(255) NOT NULL,
  PRIMARY KEY  (`ID`),
  UNIQUE KEY `User` (`User`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `cros`
--

LOCK TABLES `cros` WRITE;
/*!40000 ALTER TABLE `cros` DISABLE KEYS */;
/*!40000 ALTER TABLE `cros` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2014-05-08 18:50:48
