name: Feature request
about: Suggest an enhancement or new policy capability
title: ""
labels: enhancement
assignees: ""
body:
  - type: markdown
    attributes:
      value: |
        Thanks for suggesting a feature or improvement for InterLock.

  - type: textarea
    id: problem
    attributes:
      label: Problem to solve
      description: What gap or user need does this address?
    validations:
      required: true

  - type: textarea
    id: proposal
    attributes:
      label: Proposed solution
      description: Describe the capability you want and how it should work.
    validations:
      required: true

  - type: textarea
    id: use-case
    attributes:
      label: Example use case
      description: Show the scenario this would improve.
      placeholder: Example: blocking writes outside a workspace for coding agents.

  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
      description: What other approaches did you consider?
