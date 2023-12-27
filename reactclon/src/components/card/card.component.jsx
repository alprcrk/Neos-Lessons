const Card = ({ card }) => {
  const { imageUrl, title, description } = card;
  return (
    <div className="bg-white p-10 md:rounded-lg shadow flex flex-col items-center justify-center text-center">
      <img src={imageUrl} className="mb-6" alt={title} />
      <h6 className="font-semibold text-lg text-primary-color">{title}</h6>
      <p className="mt-2 text-sm text-gray-500">{description}</p>
    </div>
  );
};

export default Card;
