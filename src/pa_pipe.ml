(*pp camlp4orf *)
open Camlp4.PreCast.Syntax

EXTEND Gram
expr: AFTER "*"
[LEFTA
  [ e1= expr; "|>"; e2 = expr -> <:expr<  $e2$ $e1$ >>]
];

(* RIGHTA *)
expr: AFTER "*"
[RIGHTA
  [ e1= expr; "$" ; e2 = expr -> <:expr<  $e1$ $e2$ >>]
];
END
