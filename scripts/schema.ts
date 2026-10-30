import { z } from "zod";
import { planSchema } from "../src/engine.js";

console.log(JSON.stringify(z.toJSONSchema(planSchema), null, 2));
