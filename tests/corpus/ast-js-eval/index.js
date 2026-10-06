// eval(input) in a comment must not fire
const doc = "eval(x)";
eval(req.body.code);
