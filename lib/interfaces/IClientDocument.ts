/* eslint-disable semi */
import { Document } from "mongoose";
import IClient from "./IClient";

export default interface IClientDocument extends Document, IClient { };