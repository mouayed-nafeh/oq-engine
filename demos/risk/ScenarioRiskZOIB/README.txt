Scenario Risk Demo with ZOIB vulnerability functions
----------------------------------------------------

The same scenario as the ScenarioRisk demo (a M7 rupture in Nepal), run on a
small exposure of 247 assets with structural vulnerability functions using
the zero-one-inflated Beta distribution (dist="ZOIB"):

  <vulnerabilityFunction id="Wood" dist="ZOIB">
    <imls imt="PGA">0.05 0.1 0.2 ... 1.4</imls>
    <meanLRs>...</meanLRs>    mean of the loss ratio, given 0 < LR < 1
    <covLRs>...</covLRs>      coefficient of variation, given 0 < LR < 1
    <probZero>...</probZero>  probability of a loss ratio exactly 0
    <probOne>...</probOne>    probability of a loss ratio exactly 1
  </vulnerabilityFunction>

At each intensity level the loss ratio is 0 with probability probZero, 1
with probability probOne and otherwise follows a Beta distribution with the
given mean and coefficient of variation. The overall mean loss ratio is
probOne + (1 - probZero - probOne) * meanLR. For each asset and event the
engine draws the loss ratio from this mixture, so that the losses include
the undamaged buildings (zero loss) and the total losses (loss ratio 1).

Expected runtime: 5 seconds
Outputs: Ground Motion Fields, Average Asset Losses, Aggregate Asset Losses,
Aggregate Event Losses
