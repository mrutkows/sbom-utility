/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"strings"

	"github.com/mrutkows/sbom-utility/schema"
)

// Supported conjunctions and prepositions
const (
	AND  string = "AND"
	OR   string = "OR"
	WITH string = "WITH"
)

// Tokens
const (
	LEFT_PARENS   string = "("
	RIGHT_PARENS  string = ")"
	PLUS_OPERATOR string = "+"
)

//var CONJUNCTIONS = [2]string{AND, OR}

type CompoundExpression struct {
	SimpleLeft          string
	SimpleLeftHasPlus   bool
	LeftPolicy          schema.LicensePolicy
	LeftUsagePolicy     string
	SimpleRight         string
	SimpleRightHasPlus  bool
	RightPolicy         schema.LicensePolicy
	RightUsagePolicy    string
	Conjunction         string
	PrepRight           string
	PrepLeft            string
	CompoundLeft        *CompoundExpression
	CompoundRight       *CompoundExpression
	CompoundUsagePolicy string
}

func NewCompoundExpression() *CompoundExpression {
	return new(CompoundExpression)
}

func tokenizeExpression(expression string) (tokens []string) {
	expression = strings.ReplaceAll(expression, LEFT_PARENS, "( ")
	expression = strings.ReplaceAll(expression, RIGHT_PARENS, " )")
	tokens = strings.Fields(expression)
	return
}

func parseExpression(rawExpression string) *CompoundExpression {
	getLogger().Enter()
	defer getLogger().Exit()

	rootExpression := NewCompoundExpression()

	tokens := tokenizeExpression(rawExpression)
	getLogger().Debugf("Tokens: %v", tokens)

	finalIndex := parseCompoundExpression(rootExpression, tokens, 0)
	getLogger().Debugf("Parsed expression (%v): %v", finalIndex, rootExpression)

	return rootExpression
}

// TODO: This expression parser does not account for multiple conjunctions
// within a compound expression
func parseCompoundExpression(expression *CompoundExpression, tokens []string, index int) int {
	getLogger().Enter("expression:", expression)
	defer getLogger().Exit()
	var token string
	for index < len(tokens) {
		token = tokens[index]
		switch token {
		case LEFT_PARENS:
			getLogger().Debugf("[%v] LEFT_PARENS: `%v`", index, token)
			childExpression := NewCompoundExpression()

			// if we have no conjunction, this compound expression represents the "left" operand
			if expression.Conjunction == "" {
				expression.CompoundLeft = childExpression
			} else {
				// otherwise it is the "right" operand
				expression.CompoundRight = childExpression
			}

			index = parseCompoundExpression(childExpression, tokens, index+1)

			// retrieve the resolved policy from the child
			childPolicy := childExpression.CompoundUsagePolicy
			if expression.Conjunction == "" {
				expression.LeftUsagePolicy = childPolicy
			} else {
				// otherwise it is the "right" operand
				expression.RightUsagePolicy = childPolicy
			}

		case RIGHT_PARENS:
			getLogger().Debugf("[%v] RIGHT_PARENS: `%v`", index, token)
			FinalizeCompoundPolicy(expression)
			return index + 1
		case AND:
			getLogger().Debugf("[%v] AND (Conjunction): `%v`", index, token)
			expression.Conjunction = token
		case OR:
			getLogger().Debugf("[%v] OR (Conjunction): `%v`", index, token)
			expression.Conjunction = token
		case WITH:
			getLogger().Debugf("[%v] WITH (Preposition): `%v`", index, token)
			if expression.Conjunction == "" {
				expression.PrepLeft = token
			} else {
				// otherwise it is the "right" operand
				expression.PrepRight = token
			}
		default:
			getLogger().Debugf("[%v] Simple Expression: `%v`", index, token)
			// if we have no conjunction, this compound expression represents the "left" operand
			if expression.Conjunction == "" {
				if expression.PrepLeft == "" {
					expression.SimpleLeft = token
					// Also, check for the unary "plus" operator
					expression.SimpleLeftHasPlus = hasUnaryPlusOperator(token)
					// Lookup policy in hashmap
					expression.LeftUsagePolicy, expression.LeftPolicy = FindPolicyBySpdxId(token)
				} else {
					// this token is a preposition, for now overload its value
					expression.PrepLeft = token
				}

			} else {
				// otherwise it is the "right" operand
				if expression.PrepRight == "" {
					expression.SimpleRight = token
					// Also, check for the unary "plus" operator
					expression.SimpleRightHasPlus = hasUnaryPlusOperator(token)
					// Lookup policy in hashmap
					expression.RightUsagePolicy, expression.RightPolicy = FindPolicyBySpdxId(token)
				} else {
					// this token is a preposition, for now overload its value
					expression.PrepRight = token
				}
			}
		}

		index = index + 1
	}

	FinalizeCompoundPolicy(expression)
	return index
}

func FinalizeCompoundPolicy(expression *CompoundExpression) {
	getLogger().Enter()
	defer getLogger().Exit()

	switch expression.Conjunction {
	case AND:
		if expression.LeftUsagePolicy == POLICY_ALLOW &&
			expression.RightUsagePolicy == POLICY_ALLOW {
			expression.CompoundUsagePolicy = POLICY_ALLOW
		} else {
			expression.CompoundUsagePolicy = POLICY_DENY
		}
	case OR:
		if expression.LeftUsagePolicy == POLICY_ALLOW ||
			expression.RightUsagePolicy == POLICY_ALLOW {
			expression.CompoundUsagePolicy = POLICY_ALLOW
		} else {
			expression.CompoundUsagePolicy = POLICY_DENY
		}
	}
	getLogger().Debugf("(%s (%s) %s %s (%s)) == %s",
		expression.SimpleLeft,
		expression.LeftUsagePolicy,
		expression.Conjunction,
		expression.SimpleRight,
		expression.RightUsagePolicy,
		expression.CompoundUsagePolicy)
}

func hasUnaryPlusOperator(simpleExpression string) bool {
	getLogger().Enter()
	defer getLogger().Exit()
	return strings.HasSuffix(simpleExpression, PLUS_OPERATOR)
}
