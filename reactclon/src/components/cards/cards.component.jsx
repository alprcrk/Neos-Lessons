import { ContainerEl } from "common-styles";
import { useState, useEffect } from "react";
import cardDatas from "api/cards.json";
import Card from "components/card/card.component";

const Cards = () => {
  const [cards, setCards] = useState([]);

  useEffect(() => {
    setCards(cardDatas);
  }, []);

  return (
    <ContainerEl className="py-8">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {cards.length && cards.map((card) => <Card card={card} />)}
      </div>
    </ContainerEl>
  );
};

export default Cards;
